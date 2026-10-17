# Evidence Vault Acceptance Report: Signed Offline-Verifiable Evidence Bundles

## 1. Status: PASS

All Evidence Vault features, cryptographic signatures, offline standalone verifier checks, 1-byte tamper detection, ledger entry deletion rejections, and secrets scans passed with 100% test coverage.

---

## 2. Acceptance Table

| Requirement / Acceptance Item | Status | Evidence File & Line Reference | Notes |
|---|---|---|---|
| **1. Bundle collection (`ledger_segment`, `action_records`, `governance`, `containment`, `config_snapshot`)** | **PASS** | [`backend/app/evidence/bundle.py:270-348`](file:///d:/vigil-v2/vigil-v2/backend/app/evidence/bundle.py#L270-L348) | Complete bundle collector extracts ledger segment with chain proof, redacted telemetry, proposals, approvals, receipts, and containment outcomes. |
| **2. Manifest lists SHA-256 of all files, signed with Ed25519** | **PASS** | [`backend/app/evidence/bundle.py:328-360`](file:///d:/vigil-v2/vigil-v2/backend/app/evidence/bundle.py#L328-L360) | Manifest signs canonical byte representation of file hashes with Ed25519 and includes `public_key_hex`. |
| **3. Standalone verifier (`verify_bundle.py`)** | **PASS** | [`verify_bundle.py:1-255`](file:///d:/vigil-v2/vigil-v2/verify_bundle.py#L1-L255) | Depends strictly on Python standard library and `cryptography`. Validates manifest signatures, file hashes, and ledger chains. Exits non-zero on any failure. |
| **4. POST `/evidence/bundles` route with operator key** | **PASS** | [`backend/main.py:1009-1070`](file:///d:/vigil-v2/vigil-v2/backend/main.py#L1009-L1070) | Requires `X-VIGIL-Operator-Key`. Accepts `incident_id` or `from`/`to` window. Returns bundle path and SHA-256 hash. Tested in [`backend/tests/test_evidence_vault.py:265-300`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_evidence_vault.py#L265-L300). |
| **5. 1-byte tampering in ANY file fails verification** | **PASS** | [`backend/tests/test_evidence_vault.py:115-160`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_evidence_vault.py#L115-L160) | Tested on all 5 files (`ledger_segment.json`, `action_records.jsonl`, `governance.json`, `containment_outcomes.json`, `config_snapshot.json`). Every mutation produces non-zero exit code. |
| **6. Deleting a ledger line fails verification** | **PASS** | [`backend/tests/test_evidence_vault.py:163-195`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_evidence_vault.py#L163-L195) | Entry count mismatch and chain link break detect deleted ledger lines. |
| **7. Secrets scan passes & rejects leaks** | **PASS** | [`backend/tests/test_evidence_vault.py:228-262`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_evidence_vault.py#L228-L262) | Clean bundle passes. Planted tokens (`sk-...`, private keys) trigger fail-closed `SecretsDetectedError`. |
| **8. Offline verification with networking disabled** | **PASS** | [`evidence/vault/offline_verification.txt:1-13`](file:///d:/vigil-v2/vigil-v2/evidence/vault/offline_verification.txt#L1-L13) | Sockets mocked to raise `ConnectionRefusedError`. `verify_bundle.py` succeeds with returncode 0. |
| **9. Documentation on files, retention, redaction, and counsel review** | **PASS** | [`docs/EVIDENCE_VAULT.md:1-130`](file:///d:/vigil-v2/vigil-v2/docs/EVIDENCE_VAULT.md#L1-L130) | Full file descriptions, retention/redaction rules, and explicit legal counsel review notice. |

---

## 3. Files Added or Modified

| File Path | Purpose |
|---|---|
| [`backend/app/evidence/bundle.py`](file:///d:/vigil-v2/vigil-v2/backend/app/evidence/bundle.py) | Evidence Vault core: segment extraction, sanitization, secrets scanning, Ed25519 signing, and bundle packaging. |
| [`backend/app/evidence/__init__.py`](file:///d:/vigil-v2/vigil-v2/backend/app/evidence/__init__.py) | Package initialization and public exports. |
| [`verify_bundle.py`](file:///d:/vigil-v2/vigil-v2/verify_bundle.py) | Standalone verification script (standard library + `cryptography` only). |
| [`scripts/verify_bundle.py`](file:///d:/vigil-v2/vigil-v2/scripts/verify_bundle.py) | Forwarding wrapper for verify script. |
| [`backend/main.py`](file:///d:/vigil-v2/vigil-v2/backend/main.py) | Mounted `POST /evidence/bundles` operator-protected route. |
| [`backend/tests/test_evidence_vault.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_evidence_vault.py) | 8 unit tests covering bundle generation, 1-byte tampering, deleted lines, secrets scan, route security, and offline verification. |
| [`docs/EVIDENCE_VAULT.md`](file:///d:/vigil-v2/vigil-v2/docs/EVIDENCE_VAULT.md) | User and auditor documentation with retention/redaction specs and legal counsel review requirements. |
| [`evidence/vault/offline_verification.txt`](file:///d:/vigil-v2/vigil-v2/evidence/vault/offline_verification.txt) | Captured output of offline verification execution with sockets disabled. |
| [`evidence/vault/sample_bundle.tar.gz`](file:///d:/vigil-v2/vigil-v2/evidence/vault/sample_bundle.tar.gz) | Persistent sample bundle verifying clean with `verify_bundle.py`. |

---

## 4. What Is Not Verified, and Why

1. **Hardware Security Module (HSM) Key Storage**:
   - Bundles are signed with software Ed25519 keys stored securely outside the git workspace (`~/.vigil/vault_ed25519.key`). Integration with PKCS#11 or cloud KMS (e.g., AWS KMS / GCP Cloud HSM) was not required and is left for production infrastructure.
2. **Third-Party Regulatory Certifications**:
   - Mathematical proof and chain verification are validated; formal audit certifications (e.g., SOC 2 attestation or EU AI Act notified body conformity assessment) require statutory third-party audit engagements.

---

## 5. Blockers for Next Phase

- None.
