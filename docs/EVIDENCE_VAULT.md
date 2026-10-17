# Evidence Vault: Offline-Verifiable Cryptographic Evidence Bundles

The **VIGIL Evidence Vault** enables enterprises, compliance officers, and external auditors to export a complete, self-contained, offline-verifiable proof bundle for any security incident or operational time window.

A third party can verify the bundle on an air-gapped machine with **zero network access** using only Python and standard cryptographic primitives (`cryptography` library). Any byte alteration in any file, deleted ledger entry, or tampered signature is detected immediately.

---

## 1. Quickstart: Offline Verification

### Standalone CLI Execution (Zero Network Required)
The verifier script [`verify_bundle.py`](file:///d:/vigil-v2/vigil-v2/verify_bundle.py) depends strictly on the Python standard library and `cryptography`.

```bash
# Verify a directory bundle
python verify_bundle.py evidence/vault/sample_bundle

# Verify a packaged .tar.gz bundle archive
python verify_bundle.py evidence/vault/sample_bundle.tar.gz
```

### Verification Checks Performed
1. **Ed25519 Manifest Signature**: Verifies that [`manifest.json`](file:///d:/vigil-v2/vigil-v2/evidence/vault/sample_bundle/manifest.json) was signed by the declared private key without any mutation of file hashes or metadata.
2. **File Digest Integrity**: Recomputes SHA-256 for each file in the bundle and asserts 100% equivalence to the signed manifest.
3. **No Unmanifested Files**: Enforces a strict closed-world check ensuring no extra or unauthorized files exist in the bundle.
4. **Ledger Hash-Chain Proof**:
   - `first_prev_hash` links to the pre-window entry.
   - Every sequential entry computes $H_i = \text{SHA-256}(seq_i, ts_i, prev\_hash_i, record_i)$.
   - Consecutive entries enforce $prev\_hash_i = H_{i-1}$ and $seq_i = seq_{i-1} + 1$.
   - Total entry count matches the declared segment count (preventing line deletions).
   - `last_hash` links to the segment tail.

---

## 2. Evidence Bundle Structure

Every exported bundle contains 5 core artifacts plus a signed manifest:

| File Name | Purpose & Contents | Security & Redaction Invariant |
|---|---|---|
| [`manifest.json`](file:///d:/vigil-v2/vigil-v2/evidence/vault/sample_bundle/manifest.json) | The root of trust. Maps every bundled file to its SHA-256 digest, contains bundle metadata and scope, declares the signer's Ed25519 public key, and includes the `signature_hex`. | Signed with Ed25519 over canonical UTF-8 JSON. Signature excludes `signature_hex`. |
| [`ledger_segment.json`](file:///d:/vigil-v2/vigil-v2/evidence/vault/sample_bundle/ledger_segment.json) | The contiguous segment of the hash-chained audit ledger ([`backend/storage/audit_ledger.jsonl`](file:///d:/vigil-v2/vigil-v2/backend/storage/audit_ledger.jsonl)) spanning the incident or time window, including the `chain_proof` boundary hashes. | Immutable hash-chain. Deleting or modifying a single line breaks verification. |
| [`action_records.jsonl`](file:///d:/vigil-v2/vigil-v2/evidence/vault/sample_bundle/action_records.jsonl) | All observed agent interactions during the window in Schema v1 format. | Argument shapes only (`arg_shape`: keys, lengths, types). Zero raw SQL, prompts, or secrets. |
| [`governance.json`](file:///d:/vigil-v2/vigil-v2/evidence/vault/sample_bundle/governance.json) | Policy proposals synthesized for the incident, multi-party approvals, impact tier classifications, and signed Ed25519 receipts issued by the platform verifier. | Every approval audit trail records approver identity, timestamp, and proposal version. |
| [`containment_outcomes.json`](file:///d:/vigil-v2/vigil-v2/evidence/vault/sample_bundle/containment_outcomes.json) | Records of agent containment actions, gate decisions (ALLOW, DENY, HOLD), quarantine transitions, and remediation trigger sources (gate, auto, human, graph). | All containments originate strictly via the ArmorIQ gate callback. |
| [`config_snapshot.json`](file:///d:/vigil-v2/vigil-v2/evidence/vault/sample_bundle/config_snapshot.json) | Snapshot of operational parameters: ArmorIQ mode (`live`, `local-demo`, `disabled`), detection weights, EWMA smoothing parameters, app versions, and retention policies. | **Zero secrets**: All API keys, passwords, database credentials, and secrets are strictly excluded or scrubbed. |

---

## 3. Retention and Redaction Settings

### Redaction Policy
1. **Structural Shape Redaction**:
   - `ActionRecord` payloads never store plaintext tool arguments, SQL statements, system prompt injections, or tool responses.
   - Arguments are normalized into an abstract structural dictionary (`arg_shape`), e.g. `{"query": "str(45)", "limit": "int"}`.
2. **Secrets Scrubbing**:
   - Prior to bundle packaging, the export pipeline runs a regex and token scanner over all generated files.
   - Any match for private keys (`BEGIN PRIVATE KEY`), secret keys (`sk-...`), connection strings with passwords, or planted security test strings immediately aborts bundle export (`SecretsDetectedError`).
3. **Configuration Sanitization**:
   - `config_snapshot.json` captures version numbers and tuning weights only. Fields such as `armoriq_api_key`, `operator_api_key`, `containment_secret`, and `anthropic_api_key` are omitted entirely.

### Retention Settings
- **Audit Ledger**: Append-only, write-once, permanent retention on disk. Entries are never overwritten or deleted.
- **Policy Proposals**: 72-hour hard server-side expiration. Expired proposals transition to status `EXPIRED` and reject approvals with HTTP 409 Conflict.
- **Action Records**: High-frequency telemetry traces retained across configurable rolling windows (default: rolling 30-day baseline in PostgreSQL / SQLite).
- **Exported Bundles**: Stored under [`evidence/vault/`](file:///d:/vigil-v2/vigil-v2/evidence/vault/) as immutable `.tar.gz` packages.

---

## 4. API Reference: Exporting Bundles

### `POST /evidence/bundles`
Exports a signed evidence bundle for an incident or time window. Requires an operator API key.

**Request Headers**:
```http
X-VIGIL-Operator-Key: <OPERATOR_API_KEY>
Content-Type: application/json
```

**Request Body (Incident Scope)**:
```json
{
  "incident_id": "inc-2026-10-m6-exfil"
}
```

**Request Body (Time Window Scope)**:
```json
{
  "from": 1792160000.0,
  "to": 1792163600.0
}
```

**Response (HTTP 201 Created)**:
```json
{
  "bundle_id": "bundle-1792168300-a1b2c3d4",
  "bundle_dir": "evidence/vault/bundle-1792168300-a1b2c3d4",
  "bundle_path": "evidence/vault/bundle-1792168300-a1b2c3d4.tar.gz",
  "bundle_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "manifest_hash": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
  "public_key_hex": "9b835a9f6eede6e730b73ba6ff3bccb8e4cd70821012514023aadc0db7902811",
  "created_at": 1792168300.123
}
```

---

## 5. Legal & Regulatory Notice

> [!IMPORTANT]
> **Legal Review Requirement**:
> Any mapping of VIGIL evidence bundles, hash-chained audit ledgers, telemetry traces, or policy enforcement actions to specific regulatory duties or compliance standards (including, but not limited to, the European Union AI Act (Articles 12 & 14 on logging and human oversight), SOC 2 Type II Trust Services Criteria (CC6.1, CC6.8, CC7.2), HIPAA Security Rule (45 CFR § 164.312(b)), ISO/IEC 42001:2023, or the NIST AI Risk Management Framework (Govern & Map)) **must be reviewed and confirmed by qualified legal counsel**.
>
> VIGIL provides mathematical and cryptographic guarantees of evidence integrity, chain continuity, and non-repudiation, but technical immutability does not automatically constitute compliance with statutory or contractual obligations.
