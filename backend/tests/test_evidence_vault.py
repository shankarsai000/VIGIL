"""Test suite for Evidence Vault: signed, offline-verifiable evidence bundles.

Covers:
1. Bundle creation, export, and complete verification.
2. 1-byte tampering in any file fails verification.
3. Deleting a ledger entry line fails verification.
4. Tampered manifest signature fails verification.
5. Secrets scan passes on clean bundle and rejects planted identifiers/secrets.
6. POST /evidence/bundles API endpoint requires operator key and returns valid bundle.
7. Standalone verify_bundle.py CLI execution.
8. Offline execution with networking disabled.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from backend.app.evidence.bundle import (
    EvidenceVault,
    SecretsDetectedError,
    extract_ledger_segment,
    build_config_snapshot,
    scan_for_secrets,
    get_or_create_vault_ed25519_key,
)
from backend.app.runtime.ledger import AuditLedger
from backend.app.immune.records import ActionRecord
from backend.main import app
from verify_bundle import verify_bundle, verify_bundle_dir


@pytest.fixture
def temp_vault_dir(tmp_path):
    vdir = tmp_path / "vault"
    vdir.mkdir(parents=True, exist_ok=True)
    return vdir


@pytest.fixture
def populated_ledger(tmp_path):
    lpath = tmp_path / "audit_ledger.jsonl"
    ledger = AuditLedger(lpath)
    # Append 15 diverse entries
    for i in range(1, 16):
        ledger.append({
            "event_type": "TELEMETRY_OBSERVED" if i % 2 == 0 else "GATE_DECISION",
            "seq_index": i,
            "incident_id": "inc-vault-test-001" if 5 <= i <= 10 else None,
            "agent_id": "customer-bot",
            "action": "billing_database" if i == 7 else "order_status",
            "decision": "DENY" if i == 7 else "ALLOW",
            "ts": 1792160000.0 + i * 10,
        })
    return lpath


@pytest.fixture
def sample_records():
    records = []
    for i in range(10):
        records.append(
            ActionRecord(
                record_id=f"rec-{i}",
                trace_id=f"tr-{i}",
                tenant_id="tenant-acme",
                agent_id="customer-bot",
                ts=1792160000.0 + i * 10,
                mcp_id="vigil-tools",
                tool="billing_database" if i == 7 else "order_status",
                event_type="tool_call",
                arg_shape={"query": "str(25)"} if i == 7 else {"order_id": "str(8)"},
                provenance="trusted",
                prev_tool=None,
                observed_decision="DENY" if i == 7 else "ALLOW",
                label="ATTACK" if i == 7 else "BENIGN_ASSUMED",
                label_source="incident_confirmed" if i == 7 else "simulator_ground_truth",
                incident_id="inc-vault-test-001" if 5 <= i <= 9 else None,
            )
        )
    return records


def test_bundle_export_and_offline_verification(temp_vault_dir, populated_ledger, sample_records):
    """Proves that a generated bundle verifies cleanly both as directory and as tar.gz archive."""
    vault = EvidenceVault(
        ledger_path=populated_ledger,
        vault_root=temp_vault_dir,
    )

    bundle_info = vault.create_bundle(
        incident_id="inc-vault-test-001",
        action_records=sample_records,
        proposals=[{"id": "prop-101", "tool": "billing_database", "status": "APPROVED"}],
        approvals=[{"approver": "sec-officer@corp", "timestamp": 1792160050.0}],
        receipts=[{"receipt_id": "rcpt-999", "verified": True}],
        containment_outcomes=[{"agent_id": "customer-bot", "status": "QUARANTINED", "reason": "Data exfiltration"}],
    )

    bundle_dir = Path(bundle_info["bundle_dir"])
    bundle_tar = Path(bundle_info["bundle_path"])

    assert bundle_dir.exists()
    assert bundle_tar.exists()

    # Verify directory format
    ok_dir, msg_dir, code_dir = verify_bundle_dir(bundle_dir)
    assert ok_dir is True, f"Directory verification failed: {msg_dir}"
    assert code_dir == 0
    assert "VERIFICATION SUCCESSFUL" in msg_dir

    # Verify archive format
    ok_tar, msg_tar, code_tar = verify_bundle(bundle_tar)
    assert ok_tar is True, f"Archive verification failed: {msg_tar}"
    assert code_tar == 0
    assert "VERIFICATION SUCCESSFUL" in msg_tar


def test_one_byte_tampering_fails_verification(temp_vault_dir, populated_ledger, sample_records):
    """Proves that changing a single byte in ANY bundled file causes verification to fail."""
    vault = EvidenceVault(
        ledger_path=populated_ledger,
        vault_root=temp_vault_dir,
    )

    files_to_tamper = [
        "ledger_segment.json",
        "action_records.jsonl",
        "governance.json",
        "containment_outcomes.json",
        "config_snapshot.json",
    ]

    for target_file in files_to_tamper:
        # Create fresh bundle
        b_info = vault.create_bundle(
            incident_id="inc-vault-test-001",
            action_records=sample_records,
            bundle_id=f"bundle-tamper-{target_file.replace('.', '_')}",
        )
        b_dir = Path(b_info["bundle_dir"])
        target_path = b_dir / target_file

        # Mutate one byte
        raw_bytes = target_path.read_bytes()
        tampered_bytes = bytearray(raw_bytes)
        # Flip the last byte or a byte in the middle
        tampered_bytes[-2] = (tampered_bytes[-2] + 1) % 256
        target_path.write_bytes(bytes(tampered_bytes))

        ok, msg, exit_code = verify_bundle_dir(b_dir)
        assert ok is False, f"Tampered file {target_file} was unexpectedly accepted!"
        assert exit_code in (2, 3), f"Expected exit code 2 or 3, got {exit_code}"
        assert ("mismatch" in msg.lower() or "tampered" in msg.lower() or "broken" in msg.lower())


def test_deleting_ledger_line_fails_verification(temp_vault_dir, populated_ledger, sample_records):
    """Proves that deleting a ledger entry line breaks verification immediately."""
    vault = EvidenceVault(
        ledger_path=populated_ledger,
        vault_root=temp_vault_dir,
    )

    b_info = vault.create_bundle(
        incident_id="inc-vault-test-001",
        action_records=sample_records,
        bundle_id="bundle-delete-ledger-line",
    )
    b_dir = Path(b_info["bundle_dir"])
    ledger_path = b_dir / "ledger_segment.json"

    data = json.loads(ledger_path.read_text(encoding="utf-8"))
    entries = data["entries"]
    assert len(entries) >= 3

    # Delete the middle entry
    del entries[1]
    ledger_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    ok, msg, exit_code = verify_bundle_dir(b_dir)
    assert ok is False, "Bundle with deleted ledger line was unexpectedly accepted!"
    assert exit_code in (2, 3)
    assert ("mismatch" in msg.lower() or "deleted" in msg.lower() or "count" in msg.lower())


def test_tampered_manifest_signature_fails(temp_vault_dir, populated_ledger, sample_records):
    """Proves that tampering with manifest signature or payload fails cryptographic check."""
    vault = EvidenceVault(
        ledger_path=populated_ledger,
        vault_root=temp_vault_dir,
    )

    b_info = vault.create_bundle(
        incident_id="inc-vault-test-001",
        action_records=sample_records,
        bundle_id="bundle-tamper-sig",
    )
    b_dir = Path(b_info["bundle_dir"])
    manifest_path = b_dir / "manifest.json"

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    
    # Tamper 1: Alter signature hex
    original_sig = manifest["signature_hex"]
    altered_sig = "a" * len(original_sig)
    manifest["signature_hex"] = altered_sig
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    ok, msg, exit_code = verify_bundle_dir(b_dir)
    assert ok is False
    assert exit_code == 1
    assert "signature is invalid" in msg.lower()


def test_secrets_scan_passes_and_rejects_leaks(temp_vault_dir, populated_ledger, sample_records):
    """Proves that clean bundles pass secrets scanning, while planted tokens fail closed."""
    vault = EvidenceVault(
        ledger_path=populated_ledger,
        vault_root=temp_vault_dir,
    )

    # 1. Clean bundle passes
    b_info = vault.create_bundle(
        incident_id="inc-vault-test-001",
        action_records=sample_records,
        bundle_id="bundle-clean-secrets",
    )
    assert b_info["bundle_hash"] is not None

    # 2. Planted secret string fails closed
    planted_token = "sk-live-super-secret-confidential-token-9988776655"
    with pytest.raises(SecretsDetectedError):
        vault.create_bundle(
            incident_id="inc-vault-test-001",
            action_records=sample_records,
            bundle_id="bundle-leaked-token",
            planted_test_secrets=[planted_token],
            settings=type("FakeSettings", (), {
                "armoriq_mode": "disabled",
                "armoriq_agent_id": planted_token,  # Planted secret in config
            })(),
        )


def test_post_evidence_bundles_endpoint(tmp_path, monkeypatch):
    """Proves POST /evidence/bundles requires operator key and returns signed bundle."""
    from backend.app.config import settings
    op_key = "test-operator-vault-key"
    monkeypatch.setattr(settings, "operator_api_key", op_key)
    monkeypatch.setattr(settings, "audit_ledger_path", str(tmp_path / "audit_ledger.jsonl"))

    # Populate ledger
    ledger = AuditLedger(settings.audit_ledger_path)
    ledger.append({"event": "TEST_EVENT", "ts": 1792160000.0})

    client = TestClient(app)

    # 1. Unauthorized request without operator key -> 401
    resp_unauth = client.post("/evidence/bundles", json={"incident_id": "inc-001"})
    assert resp_unauth.status_code == 401

    # 2. Authorized request missing required window/incident -> 400
    resp_empty = client.post(
        "/evidence/bundles",
        json={},
        headers={"X-VIGIL-Operator-Key": op_key},
    )
    assert resp_empty.status_code == 400

    # 3. Valid authorized request -> 201
    resp_valid = client.post(
        "/evidence/bundles",
        json={"incident_id": "inc-001", "from": 1792150000.0, "to": 1792170000.0},
        headers={"X-VIGIL-Operator-Key": op_key},
    )
    assert resp_valid.status_code == 201
    data = resp_valid.json()

    assert "bundle_path" in data
    assert "bundle_hash" in data
    assert "manifest_hash" in data
    assert "public_key_hex" in data
    assert Path(data["bundle_path"]).exists()

    # Prove returned bundle verifies clean
    ok, msg, code = verify_bundle(data["bundle_path"])
    assert ok is True
    assert code == 0


def test_standalone_cli_execution(temp_vault_dir, populated_ledger, sample_records):
    """Executes verify_bundle.py as a standalone subprocess."""
    vault = EvidenceVault(
        ledger_path=populated_ledger,
        vault_root=temp_vault_dir,
    )
    b_info = vault.create_bundle(
        incident_id="inc-vault-test-001",
        action_records=sample_records,
        bundle_id="bundle-cli-test",
    )

    verify_script = Path(__file__).resolve().parent.parent.parent / "verify_bundle.py"
    assert verify_script.exists()

    # Run CLI on directory
    res_dir = subprocess.run(
        [sys.executable, str(verify_script), b_info["bundle_dir"]],
        capture_output=True,
        text=True,
    )
    assert res_dir.returncode == 0
    assert "VERIFICATION SUCCESSFUL" in res_dir.stdout

    # Run CLI on tar.gz archive
    res_tar = subprocess.run(
        [sys.executable, str(verify_script), b_info["bundle_path"]],
        capture_output=True,
        text=True,
    )
    assert res_tar.returncode == 0
    assert "VERIFICATION SUCCESSFUL" in res_tar.stdout


def test_offline_network_disabled_verification(temp_vault_dir, populated_ledger, sample_records):
    """Proves that verify_bundle.py succeeds in an environment with all network calls blocked."""
    vault = EvidenceVault(
        ledger_path=populated_ledger,
        vault_root=temp_vault_dir,
    )
    b_info = vault.create_bundle(
        incident_id="inc-vault-test-001",
        action_records=sample_records,
        bundle_id="bundle-offline-test",
    )

    # Monkeypatch socket to raise an exception on ANY connection attempt
    orig_connect = socket.socket.connect

    def blocked_connect(self, *args, **kwargs):
        raise ConnectionRefusedError("Offline verification: network connection blocked by policy!")

    with patch.object(socket.socket, "connect", blocked_connect):
        ok, msg, code = verify_bundle(b_info["bundle_path"])
        assert ok is True
        assert code == 0
        assert "VERIFICATION SUCCESSFUL" in msg

    # Save output to evidence/vault/
    evidence_vault_dir = Path("evidence/vault")
    evidence_vault_dir.mkdir(parents=True, exist_ok=True)
    out_file = evidence_vault_dir / "offline_verification.txt"
    out_file.write_text(
        f"=== VIGIL Offline Evidence Verification ===\n"
        f"Timestamp: {time.time()}\n"
        f"Target: {b_info['bundle_path']}\n"
        f"Network Status: DISABLED (all socket connections raise ConnectionRefusedError)\n"
        f"Result Code: {code}\n"
        f"Log Output:\n{msg}\n",
        encoding="utf-8",
    )
    assert out_file.exists()
