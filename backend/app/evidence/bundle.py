"""Evidence Vault: Export signed, offline-verifiable evidence bundles.

Collects:
1. The ledger segment with its chain proof (first_prev_hash, last_hash, start_seq, end_seq).
2. Redacted action_records for the window / incident (structural shapes only).
3. Proposals, approvals, and receipts.
4. Containment outcomes.
5. Config snapshot with modes and versions, and no secret values.
6. Manifest.json listing SHA-256 of every file, signed with Ed25519.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_HASH = "0" * 64
_BODY_KEYS = ("seq", "ts", "prev_hash", "record")
DEFAULT_VAULT_KEY_PATH = Path(os.path.expanduser("~/.vigil/vault_ed25519.key"))


class SecretsDetectedError(Exception):
    """Raised when a secret or private token is detected in an evidence bundle."""
    pass


class BundleExportError(Exception):
    """Raised when evidence bundle export fails."""
    pass


def get_or_create_vault_ed25519_key(key_path: Optional[Union[str, Path]] = None) -> ed25519.Ed25519PrivateKey:
    """Loads existing Ed25519 private key from path, or generates a new one.
    
    The private key lives outside the repository (default ~/.vigil/vault_ed25519.key)
    to strictly guarantee zero private keys in git.
    """
    path = Path(key_path) if key_path else DEFAULT_VAULT_KEY_PATH
    if path.exists():
        data = path.read_bytes()
        try:
            return serialization.load_pem_private_key(data, password=None)  # type: ignore
        except Exception:
            return ed25519.Ed25519PrivateKey.from_private_bytes(data[:32])

    path.parent.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem_bytes)
    return private_key


def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """Returns deterministic, sorted-key UTF-8 JSON bytes for cryptographic signing."""
    # Omit signature_hex when hashing / signing
    payload = {k: v for k, v in data.items() if k != "signature_hex"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical.encode("utf-8")


def sha256_file(path: Path) -> str:
    """Computes SHA-256 hex digest of a file on disk."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _digest_ledger_body(body: Dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def scan_for_secrets(text: str, planted_identifiers: Optional[List[str]] = None) -> List[str]:
    """Scans text for common secret patterns, tokens, private keys, or planted test strings."""
    found: List[str] = []
    
    # Check planted identifiers first
    if planted_identifiers:
        for ident in planted_identifiers:
            if ident and ident in text:
                found.append(f"Planted identifier found: {ident}")

    # General secret regexes
    patterns = [
        (r"BEGIN [A-Z ]*PRIVATE KEY", "Private Key PEM header"),
        (r"sk-[a-zA-Z0-9_\-]{20,}", "Secret token / API key (sk-...)"),
        (r"postgres://[^:\s]+:[^@\s]+@", "Postgres URL with plaintext password"),
        (r"(?i)(?:api_key|secret|password|bearer)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Credential assignment"),
    ]

    for pat, desc in patterns:
        matches = re.findall(pat, text)
        if matches:
            # Filter out known safe placeholders
            real_matches = [m for m in matches if "[REDACTED]" not in str(m) and "none" not in str(m).lower()]
            if real_matches:
                found.append(f"{desc}: {real_matches[0][:20]}...")

    return found


def extract_ledger_segment(
    ledger_path: Union[str, Path],
    from_ts: Optional[float] = None,
    to_ts: Optional[float] = None,
    incident_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Extracts a contiguous segment of the hash-chained audit ledger covering the requested scope."""
    p = Path(ledger_path)
    if not p.exists():
        return {
            "chain_proof": {
                "first_prev_hash": GENESIS_HASH,
                "last_hash": GENESIS_HASH,
                "start_seq": 0,
                "end_seq": 0,
                "total_entries": 0,
            },
            "entries": [],
        }

    all_entries: List[Dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                all_entries.append(json.loads(line_str))

    if not all_entries:
        return {
            "chain_proof": {
                "first_prev_hash": GENESIS_HASH,
                "last_hash": GENESIS_HASH,
                "start_seq": 0,
                "end_seq": 0,
                "total_entries": 0,
            },
            "entries": [],
        }

    # Filter to identify matching entry indices
    matching_indices: List[int] = []
    for idx, row in enumerate(all_entries):
        row_ts = row.get("ts", 0.0)
        rec = row.get("record", {})
        
        match_time = True
        if from_ts is not None and row_ts < from_ts:
            match_time = False
        if to_ts is not None and row_ts > to_ts:
            match_time = False

        match_inc = True
        if incident_id:
            rec_inc = rec.get("incident_id") if isinstance(rec, dict) else None
            match_inc = (rec_inc == incident_id)

        if match_time and match_inc:
            matching_indices.append(idx)

    # To maintain unbroken chain proof, select the contiguous span from min_idx to max_idx
    if matching_indices:
        start_idx = matching_indices[0]
        end_idx = matching_indices[-1]
    else:
        # If no explicit matches, export either entire ledger or latest 100 entries
        start_idx = 0
        end_idx = len(all_entries) - 1

    segment_entries = all_entries[start_idx : end_idx + 1]
    first_prev_hash = segment_entries[0].get("prev_hash", GENESIS_HASH)
    last_hash = segment_entries[-1].get("hash", GENESIS_HASH)
    start_seq = segment_entries[0].get("seq", 0)
    end_seq = segment_entries[-1].get("seq", 0)

    return {
        "chain_proof": {
            "first_prev_hash": first_prev_hash,
            "last_hash": last_hash,
            "start_seq": start_seq,
            "end_seq": end_seq,
            "total_entries": len(segment_entries),
        },
        "entries": segment_entries,
    }


def build_config_snapshot(
    settings: Optional[Any] = None,
    modes_extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Constructs a clean configuration snapshot with zero secret values."""
    armoriq_mode = getattr(settings, "armoriq_mode", "disabled") if settings else "disabled"
    agent_id = getattr(settings, "armoriq_agent_id", "vigil-containment") if settings else "vigil-containment"
    mcp_id = getattr(settings, "armoriq_containment_mcp_id", "vigil-containment") if settings else "vigil-containment"
    production = getattr(settings, "armoriq_use_production", True) if settings else True
    validity = getattr(settings, "armoriq_token_validity_seconds", 300) if settings else 300

    w_rule = getattr(settings, "weight_rule", 0.60) if settings else 0.60
    w_ewma = getattr(settings, "weight_ewma", 0.25) if settings else 0.25
    w_iforest = getattr(settings, "weight_iforest", 0.15) if settings else 0.15

    alpha = getattr(settings, "ewma_alpha", 0.10) if settings else 0.10
    cold_start = getattr(settings, "ewma_cold_start_threshold", 50) if settings else 50

    snapshot = {
        "app_name": "VIGIL Policy Immune System",
        "app_version": "2.0.0",
        "schema_version": "v1",
        "python_version": sys.version.split()[0],
        "modes": {
            "armoriq_mode": armoriq_mode,
            "armoriq_agent_id": agent_id,
            "armoriq_containment_mcp_id": mcp_id,
            "armoriq_use_production": production,
            "armoriq_token_validity_seconds": validity,
            "offline_replay_enforced": True,
            "dry_run_default": True,
        },
        "detection_parameters": {
            "weights": {
                "rule": w_rule,
                "ewma": w_ewma,
                "isolation_forest": w_iforest,
            },
            "ewma": {
                "alpha": alpha,
                "cold_start_threshold": cold_start,
            },
        },
        "retention_and_redaction": {
            "audit_ledger": "append-only immutable SHA-256 hash-chain",
            "policy_proposals": "72-hour hard server-side expiration (HTTP 409)",
            "action_records": "structural shape redaction (keys, types, lengths; zero raw payloads or secrets)",
            "secrets_scrubbing": "automatic regex scrubbing of planted tokens and auth keys",
        },
        "legal_and_regulatory_notice": (
            "Any mapping of VIGIL evidence bundles, audit ledgers, telemetry traces, or policy "
            "enforcement actions to regulatory duties (including EU AI Act, SOC 2 Type II, HIPAA, "
            "ISO 42001, or NIST AI RMF) must be reviewed and confirmed by legal counsel."
        ),
    }

    if modes_extra:
        snapshot["modes"].update(modes_extra)

    return snapshot


def sanitize_action_record_dict(rec_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures an action record dictionary contains only redacted structural shapes."""
    shape = rec_dict.get("arg_shape")
    if isinstance(shape, str):
        try:
            shape = json.loads(shape)
        except Exception:
            shape = {"type": "unparseable"}

    return {
        "record_id": rec_dict.get("record_id"),
        "trace_id": rec_dict.get("trace_id"),
        "tenant_id": rec_dict.get("tenant_id"),
        "agent_id": rec_dict.get("agent_id"),
        "ts": rec_dict.get("ts"),
        "mcp_id": rec_dict.get("mcp_id"),
        "tool": rec_dict.get("tool"),
        "event_type": rec_dict.get("event_type"),
        "arg_shape": shape,
        "provenance": rec_dict.get("provenance", "unknown"),
        "prev_tool": rec_dict.get("prev_tool"),
        "observed_decision": rec_dict.get("observed_decision", "UNOBSERVED"),
        "label": rec_dict.get("label", "BENIGN_ASSUMED"),
        "label_source": rec_dict.get("label_source", "none"),
        "incident_id": rec_dict.get("incident_id"),
    }


class EvidenceVault:
    """Manages creation, export, and cryptographic packaging of evidence bundles."""

    def __init__(
        self,
        ledger_path: Union[str, Path] = "backend/storage/audit_ledger.jsonl",
        signing_key: Optional[ed25519.Ed25519PrivateKey] = None,
        key_path: Optional[Union[str, Path]] = None,
        vault_root: Union[str, Path] = "evidence/vault",
    ):
        self.ledger_path = Path(ledger_path)
        self.vault_root = Path(vault_root)
        self.vault_root.mkdir(parents=True, exist_ok=True)
        self.private_key = signing_key or get_or_create_vault_ed25519_key(key_path)
        self.public_key = self.private_key.public_key()
        self.public_key_hex = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def create_bundle(
        self,
        incident_id: Optional[str] = None,
        from_ts: Optional[float] = None,
        to_ts: Optional[float] = None,
        action_records: Optional[List[Any]] = None,
        proposals: Optional[List[Any]] = None,
        approvals: Optional[List[Any]] = None,
        receipts: Optional[List[Any]] = None,
        containment_outcomes: Optional[List[Any]] = None,
        settings: Optional[Any] = None,
        bundle_id: Optional[str] = None,
        planted_test_secrets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Collects, serializes, verifies secrets, signs, and packages an evidence bundle."""
        ts_now = round(time.time(), 3)
        b_id = bundle_id or f"bundle-{int(ts_now)}-{os.urandom(4).hex()}"
        bundle_dir = self.vault_root / b_id
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # 1. Ledger segment with chain proof
        ledger_data = extract_ledger_segment(
            self.ledger_path,
            from_ts=from_ts,
            to_ts=to_ts,
            incident_id=incident_id,
        )
        ledger_file = bundle_dir / "ledger_segment.json"
        with open(ledger_file, "w", encoding="utf-8") as f:
            json.dump(ledger_data, f, indent=2, sort_keys=True)

        # 2. Redacted action_records
        records_file = bundle_dir / "action_records.jsonl"
        with open(records_file, "w", encoding="utf-8") as f:
            if action_records:
                for rec in action_records:
                    if is_dataclass(rec):
                        d = asdict(rec)
                    elif hasattr(rec, "model_dump"):
                        d = rec.model_dump()
                    elif isinstance(rec, dict):
                        d = rec
                    else:
                        d = dict(rec)
                    sanitized = sanitize_action_record_dict(d)
                    f.write(json.dumps(sanitized, sort_keys=True) + "\n")

        # 3. Governance (proposals, approvals, receipts)
        governance_data = {
            "proposals": proposals or [],
            "approvals": approvals or [],
            "receipts": receipts or [],
        }
        gov_file = bundle_dir / "governance.json"
        with open(gov_file, "w", encoding="utf-8") as f:
            json.dump(governance_data, f, indent=2, sort_keys=True)

        # 4. Containment outcomes
        containment_data = {
            "containment_outcomes": containment_outcomes or [],
            "incident_id": incident_id,
            "window": {"from_ts": from_ts, "to_ts": to_ts},
        }
        cont_file = bundle_dir / "containment_outcomes.json"
        with open(cont_file, "w", encoding="utf-8") as f:
            json.dump(containment_data, f, indent=2, sort_keys=True)

        # 5. Config snapshot (with no secrets)
        config_data = build_config_snapshot(settings)
        cfg_file = bundle_dir / "config_snapshot.json"
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2, sort_keys=True)

        # Secrets scan across all generated files before signing
        all_text = ""
        for p in [ledger_file, records_file, gov_file, cont_file, cfg_file]:
            all_text += p.read_text(encoding="utf-8") + "\n"

        leaks = scan_for_secrets(all_text, planted_identifiers=planted_test_secrets)
        if leaks:
            shutil.rmtree(bundle_dir, ignore_errors=True)
            raise SecretsDetectedError(f"Evidence bundle contains forbidden secrets or identifiers: {leaks}")

        # 6. Manifest creation and signing
        files_map = {
            "ledger_segment.json": sha256_file(ledger_file),
            "action_records.jsonl": sha256_file(records_file),
            "governance.json": sha256_file(gov_file),
            "containment_outcomes.json": sha256_file(cont_file),
            "config_snapshot.json": sha256_file(cfg_file),
        }

        scope = {
            "incident_id": incident_id,
            "from_ts": from_ts,
            "to_ts": to_ts,
        }

        manifest_dict = {
            "bundle_id": b_id,
            "created_at": ts_now,
            "scope": scope,
            "files": files_map,
            "public_key_hex": self.public_key_hex,
        }

        # Canonicalize bytes and sign
        canon_bytes = canonical_json_bytes(manifest_dict)
        signature = self.private_key.sign(canon_bytes)
        manifest_dict["signature_hex"] = signature.hex()

        manifest_file = bundle_dir / "manifest.json"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_dict, f, indent=2, sort_keys=True)

        manifest_hash = sha256_file(manifest_file)

        # Also package as tar.gz archive for easy transfer
        archive_path = self.vault_root / f"{b_id}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            for item in sorted(bundle_dir.iterdir()):
                tar.add(item, arcname=item.name)

        archive_hash = sha256_file(archive_path)

        return {
            "bundle_id": b_id,
            "bundle_dir": str(bundle_dir),
            "bundle_path": str(archive_path),
            "bundle_hash": archive_hash,
            "manifest_hash": manifest_hash,
            "public_key_hex": self.public_key_hex,
            "signature_hex": manifest_dict["signature_hex"],
            "files": files_map,
            "created_at": ts_now,
        }
