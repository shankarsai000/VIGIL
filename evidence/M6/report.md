# Phase M6 Report: Shared Signatures and the Demo Pack

## 1. Status: PASS

Gate: M5 offline acceptance is green. All privacy invariants, signature tampering rejections, local replay contradictions, and 2-minute demo run requirements passed.

---

## 2. Acceptance Table

| Requirement / Acceptance Criteria | Status | Evidence File & Line Reference | Notes |
|---|---|---|---|
| **1. Export privacy: contains none of planted local identifiers** | **PASS** | [`backend/tests/test_immune_signatures.py:46-107`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_signatures.py#L46-L107) | Planted tool name (`billing_database`), agent ID (`agent-super-secret-999`), tenant ID (`tenant-enterprise-financial-corp`), and secret string (`sk-live-super-confidential-token-12345`) are completely absent from the exported bundle. Motifs use only `CATEGORY:` namespace. |
| **2. Support buckets instead of exact counts** | **PASS** | [`backend/app/immune/signatures.py:38-54`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/signatures.py#L38-L54) | Raw counts are discretized into `small` (<5), `medium` (5-20), `large` (>20) to prevent leakage of incident volume. |
| **3. Tampered bundle is rejected** | **PASS** | [`backend/tests/test_immune_signatures.py:110-184`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_signatures.py#L110-L184) | Any modification to motifs, support buckets, or Ed25519 signature raises `SignatureVerificationError`. |
| **4. Contradicted motif returns REJECT or INSUFFICIENT_EVIDENCE** | **PASS** | [`backend/tests/test_immune_signatures.py:187-285`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_signatures.py#L187-L285) | If local benign traffic uses the tool, replay returns `REJECT`. If fewer than 50 benign records exist, returns `INSUFFICIENT_EVIDENCE`. |
| **5. Import never writes armoriq.yaml or calls ArmorIQ** | **PASS** | [`backend/tests/test_immune_signatures.py:288-348`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_signatures.py#L288-L348) | Mocks and file mtime snapshots prove zero HTTP calls to ArmorIQ and zero writes to configuration files. |
| **6. End-to-end demo runs in under two minutes** | **PASS** | [`evidence/M6/demo_output.txt:52`](file:///d:/vigil-v2/vigil-v2/evidence/M6/demo_output.txt#L52) | Scripted demo runs in 0.31s (< 120s limit). Covers incident, candidates, replay table, two-person approval, verification, and receipts. Supports `--offline` flag. |
| **7. Every path cited in docs exists** | **PASS** | [`evidence/M6/acceptance_check.json:1-42`](file:///d:/vigil-v2/vigil-v2/evidence/M6/acceptance_check.json#L1-L42) | Automated acceptance check confirms 100% of paths cited in `docs/` and `ENHANCEMENTS.md` exist. |
| **8. Privacy tests pass** | **PASS** | [`backend/tests/test_immune_signatures.py:1-355`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_signatures.py#L1-L355) | All 5 test cases pass in 8.12s. |

---

## 3. Files Added or Modified

| File Path | Purpose | Test / Verification File |
|---|---|---|
| [`config/tool_categories.yaml`](file:///d:/vigil-v2/vigil-v2/config/tool_categories.yaml) | Maps semantic tool categories to local tools and declares trusted public key | [`backend/tests/test_immune_signatures.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_signatures.py) |
| [`backend/app/immune/signatures.py`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/signatures.py) | Export/import of abstract category motifs, support bucketing, Ed25519 signing, privacy assertion | `backend/tests/test_immune_signatures.py` |
| [`backend/app/immune/__init__.py`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/__init__.py) | Exported signature functions and exceptions | `backend/tests/test_immune_signatures.py` |
| [`backend/tests/test_immune_signatures.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_signatures.py) | Unit test suite (privacy assertions, tamper rejection, contradiction rejection, governance invariants) | Pytest (5 passed) |
| [`scripts/demo_policy_loop.py`](file:///d:/vigil-v2/vigil-v2/scripts/demo_policy_loop.py) | End-to-end scripted demonstration with `--offline` support (< 120s) | [`evidence/M6/demo_output.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M6/demo_output.txt) |
| [`scripts/verify_m6_acceptance.py`](file:///d:/vigil-v2/vigil-v2/scripts/verify_m6_acceptance.py) | Acceptance verification runner | [`evidence/M6/acceptance_check.json`](file:///d:/vigil-v2/vigil-v2/evidence/M6/acceptance_check.json) |
| [`docs/DEMO_SCRIPT.md`](file:///d:/vigil-v2/vigil-v2/docs/DEMO_SCRIPT.md) | Ordered on-screen steps for the demonstration | Manual / scripted walkthrough |
| [`docs/POLICY_IMMUNE.md`](file:///d:/vigil-v2/vigil-v2/docs/POLICY_IMMUNE.md) | Updated with complete M0-M6 lifecycle, verification matrix, and behavioral/mathematical limits | Verification script |
| [`ENHANCEMENTS.md`](file:///d:/vigil-v2/vigil-v2/ENHANCEMENTS.md) | Updated with M0-M6 architecture, evidence paths, and limitations | Verification script |
| [`evidence/M6/demo_output.txt`](file:///d:/vigil-v2/vigil-v2/evidence/M6/demo_output.txt) | Captured output of the 0.31s demo execution | `scripts/demo_policy_loop.py` |
| [`evidence/M6/acceptance_check.json`](file:///d:/vigil-v2/vigil-v2/evidence/M6/acceptance_check.json) | Structured verification results of acceptance criteria | `scripts/verify_m6_acceptance.py` |

---

## 4. What Is Not Verified, and Why

1. **Third-Party Signature Bundle Federation**:
   - The bundle exchange was tested locally between export and import pipelines using Ed25519 signatures. A production cross-tenant federation hub (e.g. OCI registry or central distribution repo) is not deployed in this repository.
2. **Adversarial Adaptation Simulation**:
   - As stated in the mathematical limitations, counterfactual replay proves what a candidate rule would have blocked across historical traffic, but does not simulate dynamic attacker adaptation.

---

## 5. Blockers for Next Phase

- None. Phase M6 represents the completion of the VIGIL Policy Immune System project.
