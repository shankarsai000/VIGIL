# Phase M5 Report: ArmorIQ Verification and Signed Receipts

## 1. Status: PASS

Gate: M4 tests pass. Live verification executed with `ARMORIQ_MODE=live` against production ArmorIQ proxy `https://customer-proxy.armoriq.ai`. Never printed secrets. All platform denials reproduced and cryptographically verified.

---

## 2. Acceptance Table

| Requirement / Acceptance Criteria | Status | Evidence File & Line Reference | Notes |
|---|---|---|---|
| **1. FastMCP server (`vigil-tools`) on port 8791 with tunnel exposure** | **PASS** | [`demo/tools_mcp/server.py:1-68`](file:///d:/vigil-v2/vigil-v2/demo/tools_mcp/server.py#L1-L68) | Implements `billing_database(query)` and `order_status(order_id)` returning canned data. Cloudflare tunnel active at `https://counter-stationery-occasional-bargain.trycloudflare.com/mcp`. |
| **2. Preflight introspection of `armoriq_sdk`** | **PASS** | [`evidence/M5/preflight.json:1-15`](file:///d:/vigil-v2/vigil-v2/evidence/M5/preflight.json#L1-L15) | `get_intent_token` mints token successfully (`token_issued: true`). Denial raises at invoke with `PolicyBlockedException: Tool 'billing_database' denied by OPA: policy_constraints_not_satisfied`. Attributes: `enforcement_action='block'`, `reason='policy_constraints_not_satisfied'`, `layer='opa'`. |
| **3. Offline tests pass (including `IntentMismatchException` failure)** | **PASS** | [`backend/tests/test_immune_verify.py:1-137`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_verify.py#L1-L137) | All 5 tests pass in 6.48s. Verifies that `IntentMismatchException` raises `VerificationFailure` (platform policy never ran $\to$ FAILS). |
| **4. Live verification shows DENIED for every attack call** | **PASS** | [`evidence/M5/live_verification.json:16-56`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json#L16-L56) | 3 attack calls on `billing_database`: all 3 returned `DENIED`, raised `PolicyBlockedException`, `layer: "opa"`, individual `token_id`, `plan_hash`. |
| **5. Live verification shows success for every benign call** | **PASS** | [`evidence/M5/live_verification.json:57-106`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json#L57-L106) | 3 benign calls on `order_status`: all 3 returned `ALLOWED` with `platform_policy_decision: "ALLOWED"`, individual `token_id`, `plan_hash`. |
| **6. Dashboard row inspection & observed layer** | **PASS** | [`evidence/M5/live_verification.json:107-113`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json#L107-L113) | `dashboard_row_present: false`. Observed layer: `"opa"`. Platform block occurs during OPA policy evaluation before upstream execution completes. |
| **7. Ed25519 cryptographic receipts & verification** | **PASS** | [`evidence/M5/live_receipt.json:1-92`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_receipt.json#L1-L92) | Receipt signed with Ed25519. Validates with public key `f967c1bf41c92fd3...`. Tampered receipt (`attacks_denied = 0`) fails verification. |
| **8. Private key lives outside repo** | **PASS** | [`backend/app/immune/verify.py:43-70`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/verify.py#L43-L70) | Stored at `~/.vigil/receipt_ed25519.key` outside the repository workspace. |
| **9. Append receipt hash to AuditLedger** | **PASS** | [`backend/storage/audit_ledger.jsonl:10763`](file:///d:/vigil-v2/vigil-v2/backend/storage/audit_ledger.jsonl#L10763) | Event `IMMUNE_RECEIPT_ISSUED` (seq 10763) appended with SHA256 receipt digest and signature prefix. |
| **10. Onboarding: `vigil-tools.armoriq.yaml` authored and validated** | **PASS** | [`config/vigil-tools.armoriq.yaml:1-15`](file:///d:/vigil-v2/vigil-v2/config/vigil-tools.armoriq.yaml#L1-L15) | Authored from template; `armoriq validate` passed (`✓ Config syntax valid`, `✓ API key authenticated`, `✓ vigil-tools MCP reachable (2 tools)`). `armoriq policy templates` introspected. |

---

## 3. Files Added or Modified

| File Path | Purpose | Test / Verification File |
|---|---|---|
| [`demo/tools_mcp/server.py`](file:///d:/vigil-v2/vigil-v2/demo/tools_mcp/server.py) | FastMCP server named `vigil-tools` on port 8791 with `billing_database` and `order_status` | `armoriq validate --config config/vigil-tools.armoriq.yaml` |
| [`backend/app/immune/verify.py`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/verify.py) | `ArmorIQVerifier`, Ed25519 signer/verifier, `FakeArmorIQClient` offline fake, ledger logging | [`backend/tests/test_immune_verify.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_verify.py) |
| [`backend/app/immune/__init__.py`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/__init__.py) | Exported verifier and crypto primitives | `test_immune_verify.py` |
| [`backend/tests/test_immune_verify.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_verify.py) | Unit test suite covering offline fakes, `IntentMismatchException` failure, tamper detection, key location | Pytest suite (5 passed) |
| [`config/vigil-tools.armoriq.yaml`](file:///d:/vigil-v2/vigil-v2/config/vigil-tools.armoriq.yaml) | ArmorIQ MCP server configuration for `vigil-tools` | `armoriq validate` |
| [`scripts/run_m5_live.py`](file:///d:/vigil-v2/vigil-v2/scripts/run_m5_live.py) | Live verification execution runner | [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json) |
| [`evidence/M5/preflight.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/preflight.json) | Preflight introspection empirical evidence | `scripts/preflight_armoriq.py` |
| [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json) | Full live verification outcomes with 3 attack calls & 3 benign calls | `scripts/run_m5_live.py` |
| [`evidence/M5/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_receipt.json) | Signed Ed25519 verification receipt | `verify_receipt` |

---

## 4. What Is Not Verified, and Why

1. **Central Control Plane Network Registration (`https://api.armoriq.ai/iap/sdk/register`)**:
   - `armoriq register` without `--dry-run` returned HTTP 500 (`{"statusCode":500,"message":"Internal server error"}`) on ArmorIQ's central API control plane.
   - `armoriq register --dry-run` successfully produced local agent state, confirmed all 2 MCP tools reachable, and configured proxy routing.
   - Live token minting and live OPA enforcement work independently through `https://api.armoriq.ai/iap/tokens` and `https://customer-proxy.armoriq.ai/invoke`.
2. **ArmorIQ Dashboard Row Visibility for Pre-Execution Blocks**:
   - Denied calls did not appear as completed transaction rows in the customer dashboard because they were terminated directly at the OPA evaluation layer (`layer="opa"`, `action="block"`) before reaching upstream execution. This is documented and recorded in `live_verification.json` as requested.

---

## 5. Blockers for Next Phase

- None. Phase M5 is complete, verified, and all acceptance criteria have passed.
