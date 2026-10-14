"""Audit Ledger verification and tamper check script for VIGIL v2.

1. Exports live audit ledger to evidence/ledger_export.jsonl.
2. Calls GET /audit/verify against live running backend to confirm ok: True across all entries.
3. Demonstrates cryptographic tamper detection by modifying an entry in a scratch ledger,
   proving that verify() identifies the exact broken sequence number and reason.
"""

import json
import shutil
import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import httpx

from backend.app.runtime.ledger import AuditLedger

LIVE_LEDGER_PATH = Path("backend/storage/audit_ledger.jsonl")
EXPORT_PATH = Path("evidence/ledger_export.jsonl")
SCRATCH_DIR = Path("scratch")
SCRATCH_DIR.mkdir(exist_ok=True)
TAMPERED_PATH = SCRATCH_DIR / "tampered_ledger.jsonl"


def export_ledger():
    print(f"[Ledger] Exporting live ledger from {LIVE_LEDGER_PATH} to {EXPORT_PATH}...")
    shutil.copyfile(LIVE_LEDGER_PATH, EXPORT_PATH)
    lines = EXPORT_PATH.read_text(encoding="utf-8").strip().splitlines()
    print(f"  Exported {len(lines)} entries successfully.")
    return len(lines)


def verify_live_api():
    print("\n[Ledger] Verifying live endpoint GET /audit/verify...")
    res = httpx.get("http://127.0.0.1:8000/audit/verify")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    data = res.json()
    print(f"  Live verification result: ok={data['ok']}, entries={data['entries']}, bad_seq={data['bad_seq']}")
    assert data["ok"] is True
    return data


def demonstrate_tamper():
    print("\n[Ledger] Demonstrating tamper detection on scratch ledger copy...")
    # Copy live ledger to tampered_ledger
    shutil.copyfile(LIVE_LEDGER_PATH, TAMPERED_PATH)
    
    # Read rows
    rows = [json.loads(line) for line in TAMPERED_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) < 5:
        raise RuntimeError("Ledger has too few entries to run tamper demonstration")
        
    # Tamper with entry at index 10 (seq 11) by altering the score in its record
    target_idx = 10
    original_row = dict(rows[target_idx])
    tampered_seq = original_row["seq"]
    
    print(f"  Original entry at seq {tampered_seq}: score={original_row['record'].get('score')}")
    # Change score from whatever it was to 0.0001
    rows[target_idx]["record"]["score"] = 0.0001
    print(f"  Tampering entry at seq {tampered_seq}: modified score to 0.0001")
    
    with open(TAMPERED_PATH, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
            
    # Run verify on tampered ledger
    tampered_ledger = AuditLedger(TAMPERED_PATH)
    tamper_result = tampered_ledger.verify()
    
    print(f"  Verification on tampered ledger: ok={tamper_result.ok}")
    print(f"  Detected broken sequence number: {tamper_result.bad_seq} (expected {tampered_seq})")
    print(f"  Refusal reason: '{tamper_result.reason}'")
    
    assert tamper_result.ok is False
    assert tamper_result.bad_seq == tampered_seq
    
    return {
        "tampered_seq": tampered_seq,
        "tamper_result": {
            "ok": tamper_result.ok,
            "entries_checked_before_failure": tamper_result.entries,
            "bad_seq": tamper_result.bad_seq,
            "reason": tamper_result.reason,
            "last_valid_hash": tamper_result.last_hash,
        }
    }


def write_report(total_entries, live_result, tamper_info):
    report_path = Path("evidence/ledger_verification.md")
    content = f"""# VIGIL v2 — Audit Ledger Verification & Cryptographic Tamper Evidence

## 1. Overview
VIGIL maintains a continuous SHA-256 hash-chained immutable audit ledger in accordance with tamper-evident log standards. Each ledger entry computes a canonical digest over:
- `seq`: Monotonically increasing sequence number
- `ts`: Monotonic unix timestamp
- `prev_hash`: SHA-256 hash of the preceding entry (or `0*64` genesis)
- `record`: Complete policy decision context, threat vector, score, and enforcement label (`armoriq-live`)

## 2. Live Verification Results
- **Source Ledger**: `backend/storage/audit_ledger.jsonl`
- **Exported Copy**: [`evidence/ledger_export.jsonl`](file:///evidence/ledger_export.jsonl)
- **Verified via API**: `GET /audit/verify` (HTTP 200 OK)
- **Chain Validity (`ok`)**: `{live_result['ok']}`
- **Total Validated Entries**: `{live_result['entries']}`
- **Head Digest**: `{live_result['last_hash']}`
- **Broken Sequence / Gap**: `{live_result['bad_seq']}` (None)

## 3. Cryptographic Tamper Proof
To demonstrate that unauthorized modification is mathematically guaranteed to be detected:
1. A replica of the ledger was placed in a scratch workspace.
2. Entry at sequence `{tamper_info['tampered_seq']}` was modified (altered threat score).
3. The verification algorithm executed `AuditLedger.verify()`:
   - **Verification Passed**: `{tamper_info['tamper_result']['ok']}`
   - **Detected Sequence**: `{tamper_info['tamper_result']['bad_seq']}` (exact match to tampered record)
   - **Failure Reason**: `{tamper_info['tamper_result']['reason']}`
   - **Valid Preceding Blocks**: `{tamper_info['tamper_result']['entries_checked_before_failure']}` blocks
   - **Last Unbroken Hash**: `{tamper_info['tamper_result']['last_valid_hash']}`

The ledger guarantees that retroactively changing any historical decision breaks every downstream hash in the chain.
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"\n[Ledger] Verification report written to {report_path}")


if __name__ == "__main__":
    count = export_ledger()
    live = verify_live_api()
    tamper = demonstrate_tamper()
    write_report(count, live, tamper)
    print("\nP0.7 LEDGER VERIFICATION COMPLETED.")
