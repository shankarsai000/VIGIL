#!/usr/bin/env python3
"""Standalone Evidence Bundle Verifier.

Verifies signed, offline-verifiable VIGIL evidence bundles without network access.
Dependencies: Python standard library and 'cryptography' only.

Verifications:
1. Ed25519 digital signature of manifest.json matches declared public key.
2. SHA-256 digests of all bundled files match manifest values exactly.
3. No unmanifested or unexpected files exist in the bundle.
4. Hash-chained audit ledger segment integrity:
   - first_prev_hash matches the first entry's prev_hash
   - last_hash matches the last entry's hash
   - total_entries matches the exact entry count (detects deleted lines)
   - every entry's prev_hash links to the prior entry's hash
   - every entry's seq is strictly sequential (+1)
   - every entry's hash matches the canonical SHA-256 digest of its content

Exit codes:
  0: Success (all checks passed)
  1: Manifest signature verification failed
  2: File hash mismatch or missing/extra file (tampering detected)
  3: Ledger hash-chain broken or entry deleted
  4: Invalid arguments or unreadable bundle
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_HASH = "0" * 64
_BODY_KEYS = ("seq", "ts", "prev_hash", "record")


def sha256_file(path: Path) -> str:
    """Computes SHA-256 hex digest of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """Returns deterministic canonical JSON bytes omitting signature_hex."""
    payload = {k: v for k, v in data.items() if k != "signature_hex"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical.encode("utf-8")


def _digest_ledger_body(body: Dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_bundle_dir(
    bundle_dir: Path,
    expected_public_key_hex: Optional[str] = None,
) -> Tuple[bool, str, int]:
    """Verifies an unpacked bundle directory.
    
    Returns:
        (ok, message, exit_code)
    """
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        return False, f"Manifest not found: {manifest_path}", 4

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, f"Failed to parse manifest.json: {e}", 4

    # 1. Validate manifest structure
    files_map = manifest.get("files")
    pub_hex = manifest.get("public_key_hex")
    sig_hex = manifest.get("signature_hex")

    if not files_map or not pub_hex or not sig_hex:
        return False, "manifest.json missing required fields (files, public_key_hex, signature_hex)", 4

    if expected_public_key_hex and pub_hex != expected_public_key_hex:
        return False, f"Bundle public key {pub_hex} does not match expected key {expected_public_key_hex}", 1

    # 2. Check Ed25519 digital signature
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = bytes.fromhex(sig_hex)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        message = canonical_json_bytes(manifest)
        pub_key.verify(sig_bytes, message)
    except InvalidSignature:
        return False, "FAILED: Manifest Ed25519 digital signature is INVALID (tampering detected)", 1
    except Exception as e:
        return False, f"FAILED: Signature verification error: {e}", 1

    # 3. Verify file hashes
    for filename, expected_hash in files_map.items():
        file_path = bundle_dir / filename
        if not file_path.exists():
            return False, f"FAILED: Manifested file missing from bundle: {filename}", 2

        actual_hash = sha256_file(file_path)
        if actual_hash != expected_hash:
            return (
                False,
                f"FAILED: File hash mismatch for '{filename}'! Expected {expected_hash}, got {actual_hash} (content tampered)",
                2,
            )

    # 4. Check for unexpected / unmanifested files
    allowed_files = set(files_map.keys()) | {"manifest.json"}
    for child in bundle_dir.iterdir():
        if child.is_file() and child.name not in allowed_files:
            return False, f"FAILED: Unmanifested file detected in bundle: {child.name}", 2

    # 5. Verify ledger chain segment
    ledger_path = bundle_dir / "ledger_segment.json"
    if not ledger_path.exists():
        return False, "FAILED: ledger_segment.json missing from bundle", 2

    try:
        ledger_data = json.loads(ledger_path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, f"FAILED: ledger_segment.json unparseable: {e}", 3

    chain_proof = ledger_data.get("chain_proof", {})
    entries = ledger_data.get("entries", [])

    first_prev_hash = chain_proof.get("first_prev_hash")
    last_hash = chain_proof.get("last_hash")
    start_seq = chain_proof.get("start_seq")
    end_seq = chain_proof.get("end_seq")
    total_entries = chain_proof.get("total_entries")

    if total_entries is None or first_prev_hash is None or last_hash is None:
        return False, "FAILED: ledger_segment.json missing chain_proof fields", 3

    if len(entries) != total_entries:
        return (
            False,
            f"FAILED: Ledger line count mismatch! Chain proof declares {total_entries} entries, found {len(entries)} (ledger entry deleted or added)",
            3,
        )

    if total_entries == 0:
        if first_prev_hash != last_hash:
            return False, "FAILED: Empty ledger segment has mismatched proof hashes", 3
    else:
        # Check start and end boundaries
        if entries[0].get("prev_hash") != first_prev_hash:
            return (
                False,
                f"FAILED: Ledger segment start link broken! Entry 0 prev_hash '{entries[0].get('prev_hash')}' != chain proof first_prev_hash '{first_prev_hash}'",
                3,
            )
        if entries[0].get("seq") != start_seq:
            return (
                False,
                f"FAILED: Ledger segment start sequence mismatch! Expected {start_seq}, got {entries[0].get('seq')}",
                3,
            )
        if entries[-1].get("hash") != last_hash:
            return (
                False,
                f"FAILED: Ledger segment end hash mismatch! Expected {last_hash}, got {entries[-1].get('hash')}",
                3,
            )
        if entries[-1].get("seq") != end_seq:
            return (
                False,
                f"FAILED: Ledger segment end sequence mismatch! Expected {end_seq}, got {entries[-1].get('seq')}",
                3,
            )

        # Check contiguous links and content digests
        for i, entry in enumerate(entries):
            current_seq = entry.get("seq")
            current_hash = entry.get("hash")
            current_prev = entry.get("prev_hash")

            if i > 0:
                prev_entry = entries[i - 1]
                if current_seq != prev_entry.get("seq") + 1:
                    return (
                        False,
                        f"FAILED: Ledger sequence gap or duplicate at row {i}! Seq {current_seq} follows {prev_entry.get('seq')}",
                        3,
                    )
                if current_prev != prev_entry.get("hash"):
                    return (
                        False,
                        f"FAILED: Ledger chain broken at row {i}! Entry prev_hash '{current_prev}' != previous hash '{prev_entry.get('hash')}'",
                        3,
                    )

            # Recompute canonical hash of body
            body = {k: entry.get(k) for k in _BODY_KEYS}
            computed_digest = _digest_ledger_body(body)
            if computed_digest != current_hash:
                return (
                    False,
                    f"FAILED: Ledger entry {current_seq} content tampered! Computed digest {computed_digest} != entry hash {current_hash}",
                    3,
                )

    success_msg = (
        f"VERIFICATION SUCCESSFUL: Bundle '{manifest.get('bundle_id')}'\n"
        f"  [OK] Manifest Ed25519 digital signature verified\n"
        f"  [OK] All {len(files_map)} files verified against SHA-256 manifest digests\n"
        f"  [OK] Zero unmanifested files found\n"
        f"  [OK] Ledger hash-chain verified ({total_entries} contiguous entries, seq {start_seq}..{end_seq})\n"
        f"  [OK] Signer public key: {pub_hex}"
    )
    return True, success_msg, 0


def verify_bundle(
    target_path: Union[str, Path],
    expected_public_key_hex: Optional[str] = None,
) -> Tuple[bool, str, int]:
    """Verifies an evidence bundle from a directory or .tar.gz archive."""
    p = Path(target_path)
    if not p.exists():
        return False, f"Target path does not exist: {p}", 4

    if p.is_dir():
        return verify_bundle_dir(p, expected_public_key_hex)
    elif tarfile.is_tarfile(p):
        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(p, "r:*") as tar:
                tar.extractall(path=tmpdir)
            return verify_bundle_dir(Path(tmpdir), expected_public_key_hex)
    else:
        return False, f"Unsupported bundle format (expected directory or tar.gz archive): {p}", 4


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VIGIL Evidence Vault — Standalone Offline Evidence Bundle Verifier"
    )
    parser.add_argument("bundle_path", help="Path to evidence bundle directory or .tar.gz archive")
    parser.add_argument(
        "--public-key",
        default=None,
        help="Optional expected Ed25519 public key in hex (for cross-checking authority)",
    )
    args = parser.parse_args()

    ok, msg, exit_code = verify_bundle(args.bundle_path, expected_public_key_hex=args.public_key)
    if ok:
        print(msg)
        sys.exit(0)
    else:
        print(msg, file=sys.stderr)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
