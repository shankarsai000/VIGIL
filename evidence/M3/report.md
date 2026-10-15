# Phase M3: Candidate Rules and the Dry-Run Compiler Report

## 1. Acceptance Table

| Item / Acceptance Criterion | Description | Status | Exact Evidence File & Line |
|---|---|---|---|
| **Build Item 1** | `backend/app/immune/candidates.py`: Group ATTACK records by `(agent_id, tool)`, evaluate via replay, keep `ACCEPT`, `INSUFFICIENT_EVIDENCE`, `REJECT`. Mark families separating only by argument value as `NOT_ENFORCEABLE` ("ArmorIQ globs match tools, not argument values"). | PASS | [`backend/app/immune/candidates.py:46-168`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/candidates.py#L46-L168)<br>[`backend/tests/test_immune_compiler.py:48-185`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_compiler.py#L48-L185) |
| **Build Item 2a** | `backend/app/immune/compiler.py`: armoriq.yaml patch in dot notation `<mcp>.<tool>` under `policy.deny`, one file per agent | PASS | [`backend/app/immune/compiler.py:91-155`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/compiler.py#L91-L155)<br>[`evidence/M3/customer-bot.armoriq.yaml:1-12`](file:///d:/vigil-v2/vigil-v2/evidence/M3/customer-bot.armoriq.yaml#L1-L12) |
| **Build Item 2b** | SDK inline policy in slash notation `{"allow": [...], "deny": ["<mcp>/<tool>", ...]}` | PASS | [`backend/app/immune/compiler.py:157-160`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/compiler.py#L157-L160)<br>[`evidence/M3/customer-bot.inline_policy.json:1-6`](file:///d:/vigil-v2/vigil-v2/evidence/M3/customer-bot.inline_policy.json#L1-L6) |
| **Build Item 2c** | Manifest with proposal ID, `ReplayReport`, and assumptions block (exchangeability, benign baseline, window bounds) | PASS | [`backend/app/immune/compiler.py:162-187`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/compiler.py#L162-L187)<br>[`evidence/M3/customer-bot.manifest.json:1-57`](file:///d:/vigil-v2/vigil-v2/evidence/M3/customer-bot.manifest.json#L1-L57) |
| **Build Item 3** | Dry-run by default (`write=False`). `--write` strictly requires status `APPROVED` and approval count demanded by impact tier (LOW=1, MEDIUM=1, HIGH=2, CRITICAL=2); otherwise refuses and exits non-zero. | PASS | [`backend/app/immune/compiler.py:189-231`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/compiler.py#L189-L231)<br>[`backend/app/immune/compiler.py:255-270`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/compiler.py#L255-L270)<br>[`backend/tests/test_immune_compiler.py:270-340`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_compiler.py#L270-L340) |
| **Build Item 4** | Checked `armoriq --help`, `armoriq validate --help`, `armoriq register --help`. Used only valid flags (`--config`). | PASS | [`evidence/M3/armoriq_validate_output.txt:1-8`](file:///d:/vigil-v2/vigil-v2/evidence/M3/armoriq_validate_output.txt#L1-L8) |
| **Build Item 5** | Reused name-safety check from `synthesis.py`. Refuse any tool name that is not a plain identifier. | PASS | [`backend/app/immune/candidates.py:25`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/candidates.py#L25)<br>[`backend/app/immune/compiler.py:28-29`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/compiler.py#L28-L29)<br>[`backend/tests/test_immune_compiler.py:342-365`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_compiler.py#L342-L365) |
| **Acceptance 1** | Golden-file tests for YAML patch and inline policy | PASS | [`backend/tests/test_immune_compiler.py:187-248`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_compiler.py#L187-L248)<br>[`evidence/M3/golden_customer_bot.armoriq.yaml`](file:///d:/vigil-v2/vigil-v2/evidence/M3/golden_customer_bot.armoriq.yaml)<br>[`evidence/M3/golden_customer_bot.inline_policy.json`](file:///d:/vigil-v2/vigil-v2/evidence/M3/golden_customer_bot.inline_policy.json) |
| **Acceptance 2** | Idempotence: running compiler twice gives identical bytes (`yaml_bytes`, `inline_policy_bytes`, `manifest_bytes`) | PASS | [`backend/tests/test_immune_compiler.py:250-285`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_compiler.py#L250-L285) |
| **Acceptance 3** | Dry-run writes nothing. Filesystem state compared before and after execution (0 files created/modified). | PASS | [`backend/tests/test_immune_compiler.py:287-308`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_compiler.py#L287-L308) |
| **Acceptance 4** | `--write` without approval exits non-zero (both Python API and CLI invocation) | PASS | [`backend/tests/test_immune_compiler.py:310-340`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_compiler.py#L310-L340) |
| **Acceptance 5** | Run `armoriq validate` on generated file. Recorded `BLOCKED` due to unauthenticated CLI credentials (`API key is empty`). Schema and config syntax verified valid. | BLOCKED | [`evidence/M3/armoriq_validate_output.txt:1-8`](file:///d:/vigil-v2/vigil-v2/evidence/M3/armoriq_validate_output.txt#L1-L8)<br>[`backend/tests/test_immune_compiler.py:367-425`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_compiler.py#L367-L425) |

---

## 2. Files Added or Modified

| File | Change Type | Line Count | Reason |
|---|---|---|---|
| `backend/app/immune/candidates.py` | Added | 175 | Candidate rule extractor grouping ATTACK records by `(agent_id, tool)`, evaluating via replay, and enforcing `NOT_ENFORCEABLE` on argument-separated families. |
| `backend/app/immune/compiler.py` | Added | 275 | ArmorIQ policy dry-run compiler producing dot-notation YAML patches, slash-notation inline policies, and execution manifests with impact-tier approval gates. |
| `backend/app/immune/__init__.py` | Modified | +25 | Exported candidates and compiler classes and helper methods. |
| `backend/tests/test_immune_compiler.py` | Added | 425 | Comprehensive acceptance suite covering candidate triage, golden files, idempotence, dry-run filesystem checks, approval enforcement, and CLI validation. |
| `evidence/M3/customer-bot.armoriq.yaml` | Added | 12 | Compiled ArmorIQ policy deny patch in dot notation for agent `customer-bot`. |
| `evidence/M3/customer-bot.inline_policy.json` | Added | 6 | Compiled SDK inline policy in slash notation for agent `customer-bot`. |
| `evidence/M3/customer-bot.manifest.json` | Added | 57 | Compiled proposal manifest with replay reports and exchangeability assumptions. |
| `evidence/M3/golden_customer_bot.armoriq.yaml` | Added | 12 | Golden reference YAML file for compiler regression verification. |
| `evidence/M3/golden_customer_bot.inline_policy.json` | Added | 6 | Golden reference inline policy file for SDK format verification. |
| `evidence/M3/armoriq_validate_output.txt` | Added | 8 | Captured output from `armoriq validate --config customer-bot.armoriq.yaml` showing valid syntax and unauthenticated credential block. |
| `evidence/M3/backend_tests_offline.txt` | Added | 95 | Complete offline test suite execution output (87 passed, 3 deselected). |
| `evidence/M3/report.md` | Added | ~85 | Phase M3 acceptance and verification report. |

---

## 3. What is Not Verified and Why

1. **Live Remote `armoriq validate` and `armoriq register`**:
   - Running `armoriq validate` executes syntax parsing (which succeeded: `✓ Config syntax valid`), but then attempts live credential validation against the ArmorIQ control plane. Without a live authenticated API key in the environment, the CLI exits with `Error: API key is empty. Set ARMORIQ_API_KEY or update identity.api_key.`. As explicitly instructed in the phase prompt, this is recorded as **BLOCKED**.
2. **Writing Outside `evidence/`**:
   - Per standing rules and M3 specification ("Write nothing outside the evidence folder"), the compiler's output directory defaults to `evidence/M3` and no files are written to production agent directories (`config/`).

---

## 4. Blockers for Next Phase

- **None**: All M3 implementation items and offline acceptance criteria passed. The compiler is dry-run by default, enforces impact-tier multi-party approvals before writing, generates byte-for-byte idempotent outputs, and respects name-safety identifiers.
