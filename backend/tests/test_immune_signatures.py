"""Tests for Shared Signatures and Cross-Tenant Motifs (Phase M6).

Verifies:
1. Export contains NONE of the planted local identifiers (tool names, agent IDs, tenant ID, secret string).
2. A tampered bundle is rejected with SignatureVerificationError.
3. An imported motif that local benign evidence contradicts comes back REJECT or INSUFFICIENT_EVIDENCE.
4. Import never writes armoriq.yaml and never calls ArmorIQ.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from backend.app.immune.records import ActionRecord
from backend.app.immune.signatures import (
    BUCKET_LARGE,
    BUCKET_MEDIUM,
    BUCKET_SMALL,
    PrivacyViolationError,
    SignatureVerificationError,
    count_to_support_bucket,
    export_signature_bundle,
    import_signature_bundle,
)
from backend.app.immune.verify import get_or_create_ed25519_key


@pytest.fixture
def test_ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def mapping_file_path(tmp_path):
    config_path = tmp_path / "tool_categories.yaml"
    content = """version: v1
public_key_hex: "dummy"
categories:
  secret_read:
    - mcp: "vigil-tools"
      tool: "billing_database"
  external_send:
    - mcp: "customer-bot"
      tool: "exfiltrate_data"
  order_management:
    - mcp: "vigil-tools"
      tool: "order_status"
"""
    config_path.write_text(content, encoding="utf-8")
    return str(config_path)


def test_export_contains_none_of_planted_identifiers(test_ed25519_key, mapping_file_path):
    """Guarantees that tool names, agent IDs, tenant IDs, argument values, and secrets never leak."""
    planted_tool = "billing_database"
    planted_agent = "agent-super-secret-999"
    planted_tenant = "tenant-enterprise-financial-corp"
    planted_secret = "sk-live-super-confidential-token-12345"

    records = [
        ActionRecord(
            record_id=f"rec-{i}",
            trace_id=f"trace-{i}",
            tenant_id=planted_tenant,
            agent_id=planted_agent,
            ts=1700000000.0 + i,
            mcp_id="vigil-tools",
            tool=planted_tool,
            event_type="tool_invoke",
            arg_shape={"query": "str", "length": 42},
            provenance="untrusted_content",
            prev_tool=None,
            observed_decision="ALLOW",
            label="ATTACK",
            label_source="simulator_ground_truth",
            incident_id=planted_secret,
        )
        for i in range(8)
    ]

    bundle = export_signature_bundle(
        records=records,
        mapping_path=mapping_file_path,
        private_key=test_ed25519_key,
        planted_identifiers=[planted_tool, planted_agent, planted_tenant, planted_secret],
    )

    serialized = json.dumps(bundle)

    # 1. Assert NONE of the planted identifiers appear in the exported bundle
    assert planted_tool not in serialized
    assert planted_agent not in serialized
    assert planted_tenant not in serialized
    assert planted_secret not in serialized

    # 2. Assert no timestamps or raw records appear
    assert "1700000000" not in serialized
    assert "arg_shape" not in serialized
    assert "rec-" not in serialized

    # 3. Assert motifs use only CATEGORY: namespace
    assert len(bundle["motifs"]) >= 1
    for motif in bundle["motifs"]:
        assert motif["pattern"].startswith("CATEGORY:")
        assert motif["target_category"].startswith("CATEGORY:")
        # 8 occurrences falls into 'medium' support bucket (5-20)
        assert motif["support_bucket"] == BUCKET_MEDIUM

    # 4. Verify PrivacyViolationError is raised if an identifier is artificially forced in
    with pytest.raises(PrivacyViolationError):
        bundle_leaked = dict(bundle)
        bundle_leaked["leaked_info"] = planted_secret
        from backend.app.immune.signatures import assert_bundle_privacy
        assert_bundle_privacy(bundle_leaked, planted_identifiers=[planted_secret])


def test_tampered_bundle_rejected(test_ed25519_key, mapping_file_path):
    """Verifies that tampering with bundle content or signature causes rejection."""
    records = [
        ActionRecord(
            record_id=f"rec-{i}",
            trace_id="trace-1",
            tenant_id="tenant-1",
            agent_id="agent-1",
            ts=1000.0,
            mcp_id="vigil-tools",
            tool="billing_database",
            event_type="tool_invoke",
            arg_shape={},
            provenance="untrusted_content",
            label="ATTACK",
            label_source="simulator_ground_truth",
        )
        for i in range(5)
    ]

    bundle = export_signature_bundle(
        records=records,
        mapping_path=mapping_file_path,
        private_key=test_ed25519_key,
    )
    pub_hex = bundle["public_key_hex"]

    local_records = [
        ActionRecord(
            record_id=f"benign-{i}",
            trace_id="trace-b",
            tenant_id="tenant-local",
            agent_id="customer-bot",
            ts=2000.0 + i,
            mcp_id="vigil-tools",
            tool="order_status",
            event_type="tool_invoke",
            arg_shape={},
            provenance="trusted",
            label="BENIGN_ASSUMED",
            label_source="simulator_ground_truth",
        )
        for i in range(60)
    ]

    # Valid bundle imports successfully
    result = import_signature_bundle(
        bundle_dict=bundle,
        local_records=local_records,
        mapping_path=mapping_file_path,
        target_agent_id="customer-bot",
        public_key_hex=pub_hex,
    )
    assert result["candidates_mapped"] >= 1

    # Tampered payload (altering support bucket or motifs)
    tampered_bundle = json.loads(json.dumps(bundle))
    tampered_bundle["motifs"][0]["support_bucket"] = "large"

    with pytest.raises(SignatureVerificationError):
        import_signature_bundle(
            bundle_dict=tampered_bundle,
            local_records=local_records,
            mapping_path=mapping_file_path,
            public_key_hex=pub_hex,
        )

    # Tampered signature
    tampered_sig_bundle = json.loads(json.dumps(bundle))
    tampered_sig_bundle["signature_hex"] = "aa" * 64

    with pytest.raises(SignatureVerificationError):
        import_signature_bundle(
            bundle_dict=tampered_sig_bundle,
            local_records=local_records,
            mapping_path=mapping_file_path,
            public_key_hex=pub_hex,
        )


def test_imported_motif_contradicted_by_local_benign_evidence(test_ed25519_key, mapping_file_path):
    """An imported motif that local benign evidence contradicts returns REJECT or INSUFFICIENT_EVIDENCE."""
    # Bundle contains motif targeting secret_read (maps to billing_database)
    records = [
        ActionRecord(
            record_id=f"rec-{i}",
            trace_id="trace-1",
            tenant_id="tenant-remote",
            agent_id="remote-agent",
            ts=1000.0,
            mcp_id="vigil-tools",
            tool="billing_database",
            event_type="tool_invoke",
            arg_shape={},
            provenance="untrusted_content",
            label="ATTACK",
            label_source="simulator_ground_truth",
        )
        for i in range(10)
    ]
    bundle = export_signature_bundle(
        records=records,
        mapping_path=mapping_file_path,
        private_key=test_ed25519_key,
    )
    pub_hex = bundle["public_key_hex"]

    # 1. Contradiction with sufficient sample size:
    # 650 benign events where billing_database is used, plus 5 attack records on billing_database
    contradictory_local_records = [
        ActionRecord(
            record_id=f"benign-{i}",
            trace_id="trace-local",
            tenant_id="tenant-local",
            agent_id="customer-bot",
            ts=2000.0 + i,
            mcp_id="vigil-tools",
            tool="billing_database",  # Local agent uses it legitimately!
            event_type="tool_invoke",
            arg_shape={},
            provenance="trusted",
            label="BENIGN_ASSUMED",
            label_source="simulator_ground_truth",
        )
        for i in range(650)
    ] + [
        ActionRecord(
            record_id=f"attack-local-{i}",
            trace_id="trace-attack",
            tenant_id="tenant-local",
            agent_id="customer-bot",
            ts=3000.0 + i,
            mcp_id="vigil-tools",
            tool="billing_database",
            event_type="tool_invoke",
            arg_shape={},
            provenance="untrusted_content",
            label="ATTACK",
            label_source="simulator_ground_truth",
        )
        for i in range(5)
    ]

    res_rejected = import_signature_bundle(
        bundle_dict=bundle,
        local_records=contradictory_local_records,
        mapping_path=mapping_file_path,
        target_agent_id="customer-bot",
        public_key_hex=pub_hex,
    )

    # Replay engine detects that blocking billing_database causes false blocks and rejects it!
    assert res_rejected["rejected_count"] >= 1
    assert res_rejected["accepted_count"] == 0
    assert any(e.status == "REJECT" for e in res_rejected["evaluations"])
    assert any(e.false_block_point > 0.0 for e in res_rejected["evaluations"])

    # 2. Insufficient evidence: Fewer than 50 benign events
    scant_local_records = [
        ActionRecord(
            record_id=f"benign-{i}",
            trace_id="trace-local",
            tenant_id="tenant-local",
            agent_id="customer-bot",
            ts=2000.0 + i,
            mcp_id="vigil-tools",
            tool="order_status",
            event_type="tool_invoke",
            arg_shape={},
            provenance="trusted",
            label="BENIGN_ASSUMED",
            label_source="simulator_ground_truth",
        )
        for i in range(20)  # Only 20 events < 50 threshold
    ]

    res_insufficient = import_signature_bundle(
        bundle_dict=bundle,
        local_records=scant_local_records,
        mapping_path=mapping_file_path,
        target_agent_id="customer-bot",
        public_key_hex=pub_hex,
    )

    assert res_insufficient["insufficient_count"] >= 1
    assert res_insufficient["accepted_count"] == 0
    assert any(e.status == "INSUFFICIENT_EVIDENCE" for e in res_insufficient["evaluations"])


def test_import_never_writes_armoriq_yaml_or_calls_armoriq(test_ed25519_key, mapping_file_path, tmp_path):
    """Guarantees fail-closed governance: import is purely advisory and NEVER modifies live config."""
    records = [
        ActionRecord(
            record_id=f"rec-{i}",
            trace_id="trace-1",
            tenant_id="tenant-1",
            agent_id="agent-1",
            ts=1000.0,
            mcp_id="vigil-tools",
            tool="billing_database",
            event_type="tool_invoke",
            arg_shape={},
            provenance="untrusted_content",
            label="ATTACK",
            label_source="simulator_ground_truth",
        )
        for i in range(5)
    ]
    bundle = export_signature_bundle(
        records=records,
        mapping_path=mapping_file_path,
        private_key=test_ed25519_key,
    )
    pub_hex = bundle["public_key_hex"]

    local_records = [
        ActionRecord(
            record_id=f"benign-{i}",
            trace_id="trace-b",
            tenant_id="tenant-local",
            agent_id="customer-bot",
            ts=2000.0 + i,
            mcp_id="vigil-tools",
            tool="order_status",
            event_type="tool_invoke",
            arg_shape={},
            provenance="trusted",
            label="BENIGN_ASSUMED",
            label_source="simulator_ground_truth",
        )
        for i in range(60)
    ]

    # Snapshot config directory files and modification times
    config_dir = Path("config")
    existing_files = {p: p.stat().st_mtime for p in config_dir.glob("*.yaml")}

    # Mock any potential network/subprocess or armoriq calls
    with patch("subprocess.run") as mock_subproc, \
         patch("httpx.Client.post") as mock_post:
        result = import_signature_bundle(
            bundle_dict=bundle,
            local_records=local_records,
            mapping_path=mapping_file_path,
            target_agent_id="customer-bot",
            public_key_hex=pub_hex,
        )

        # Assert no subprocess (e.g. armoriq CLI) was executed
        assert mock_subproc.call_count == 0
        # Assert no HTTP POST to ArmorIQ control plane was made
        assert mock_post.call_count == 0

    # Assert no files were created or modified in config/
    for p, orig_mtime in existing_files.items():
        assert p.stat().st_mtime == orig_mtime
    new_files = set(config_dir.glob("*.yaml")) - set(existing_files.keys())
    # tool_categories.yaml was created earlier in config/, verify no armoriq.yaml or write-back occurred
    assert not any("armoriq" in f.name for f in new_files)


def test_support_bucket_discretization():
    """Confirms discrete bucketing boundaries."""
    assert count_to_support_bucket(1) == BUCKET_SMALL
    assert count_to_support_bucket(4) == BUCKET_SMALL
    assert count_to_support_bucket(5) == BUCKET_MEDIUM
    assert count_to_support_bucket(20) == BUCKET_MEDIUM
    assert count_to_support_bucket(21) == BUCKET_LARGE
    assert count_to_support_bucket(500) == BUCKET_LARGE
