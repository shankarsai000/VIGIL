# VIGIL v2 — Audit Ledger Verification & Cryptographic Tamper Evidence

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
- **Chain Validity (`ok`)**: `True`
- **Total Validated Entries**: `2023`
- **Head Digest**: `efb4b0cff50906358a7bede9294259a70cab4b408b4525fe70cd6f7705f4ba6d`
- **Broken Sequence / Gap**: `None` (None)

## 3. Cryptographic Tamper Proof
To demonstrate that unauthorized modification is mathematically guaranteed to be detected:
1. A replica of the ledger was placed in a scratch workspace.
2. Entry at sequence `11` was modified (altered threat score).
3. The verification algorithm executed `AuditLedger.verify()`:
   - **Verification Passed**: `False`
   - **Detected Sequence**: `11` (exact match to tampered record)
   - **Failure Reason**: `entry content does not match its hash`
   - **Valid Preceding Blocks**: `10` blocks
   - **Last Unbroken Hash**: `b469df83f547e2585149de884a081e02fd947078c92768f48127e8a1e89dadb7`

The ledger guarantees that retroactively changing any historical decision breaks every downstream hash in the chain.
