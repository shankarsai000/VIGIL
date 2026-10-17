# Phase V1 Final Report: Provenance and Lineage Tracking with DIFC Taint

## Summary
Phase V1 implements decentralized information flow control (DIFC) and cryptographic lineage tracking for multi-agent delegations. Taint propagates monotonically along delegation edges and never decreases. VIGIL derives inline denial policies for restricted sinks when lineage taint exceeds the sink ceiling, passes them into ArmorIQ intent token minting, and ArmorIQ OPA policy enforcement blocks privileged sink execution at invocation time.

---

## Acceptance Table

| Item | Requirement / Step | Status | Evidence Path |
|---|---|---|---|
| **V1-01** | Lineage data structures (`TaintLevel`, `LineageRecord`, graph walk) | **PASS** | [`backend/app/provenance/lineage.py`](file:///d:/vigil-v2/vigil-v2/backend/app/provenance/lineage.py) |
| **V1-02** | Monotonic taint propagation unit test | **PASS** | [`backend/tests/test_provenance_lineage.py:L14-L44`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_provenance_lineage.py#L14-L44) |
| **V1-03** | Cycle detection marks lineage DEGRADED | **PASS** | [`backend/tests/test_provenance_lineage.py:L47-L69`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_provenance_lineage.py#L47-L69) |
| **V1-04** | Depth limit overflow marks lineage DEGRADED | **PASS** | [`backend/tests/test_provenance_lineage.py:L72-L93`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_provenance_lineage.py#L72-L93) |
| **V1-05** | Missing lineage fails closed with sink deny policy | **PASS** | [`backend/tests/test_provenance_lineage.py:L96-L109`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_provenance_lineage.py#L96-L109) |
| **V1-06** | Offline golden file for tainted lineage deny policy | **PASS** | [`evidence/V1/golden_tainted_policy.json`](file:///d:/vigil-v2/vigil-v2/evidence/V1/golden_tainted_policy.json) |
| **V1-07** | Static test: Zero client-side tool authorization decisions | **PASS** | [`backend/tests/test_static_tool_decision_boundary.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_static_tool_decision_boundary.py) |
| **V1-08** | Benign delegation benchmark (2,000 delegations, $\le 0.002$ bound) | **PASS** | [`backend/tests/test_provenance_lineage.py:L142-L179`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_provenance_lineage.py#L142-L179) (0 false taints in 2,000; 95% upper bound = 0.001496) |
| **V1-09** | Live ArmorIQ enforcement of tainted delegation | **PASS** | [`evidence/V1/live_taint_enforcement.json`](file:///d:/vigil-v2/vigil-v2/evidence/V1/live_taint_enforcement.json) (`PolicyBlockedException: Tool 'billing_database' denied by OPA`) |

---

## Files Added or Modified

| File | Change | Lines | Rationale |
|---|---|---|---|
| `config/sinks.yaml` | Added | 38 | Configured sink privilege ceilings and maximum allowed taint levels |
| `backend/app/provenance/__init__.py` | Added | 8 | Exported public provenance classes and functions |
| `backend/app/provenance/lineage.py` | Added | 231 | Core DIFC lineage tracking, cycle detection, ledger logging, and mint policy derivation |
| `backend/tests/test_provenance_lineage.py` | Added | 185 | 7 unit and benchmark tests for lineage and DIFC propagation |
| `backend/tests/test_static_tool_decision_boundary.py` | Added | 85 | AST test enforcing that only ArmorIQ makes tool-call block decisions |
| `evidence/V1/golden_tainted_policy.json` | Added | 18 | Offline golden policy fixture demonstrating taint-derived sink deny |
| `scripts/verify_live_v1_taint.py` | Added | 151 | Live test script capturing plan, minting token with taint policy, and invoking proxy |
| `evidence/V1/live_taint_enforcement.json` | Added | 22 | Live execution receipt from customer-proxy.armoriq.ai confirming OPA policy block |
| `evidence/V1/report.md` | Added | 52 | Phase V1 compliance report |

---

## What is Not Verified and Why
- **Mint-Time Rejection vs Invoke-Time Rejection**: In accordance with the empirical findings in `evidence/P1/mint_probe.json`, ArmorIQ's SDK/platform attaches the policy at token issuance (`get_intent_token`) and strictly enforces the policy at invocation (`invoke_with_policy`). The system correctly documents this behavior: taint policies are minted onto the token and enforced by ArmorIQ OPA at execution time.

---

## Blockers for Next Phase
- None. Phase V1 acceptance criteria are satisfied. Ready to proceed to Phase V2 (`v2-containment`).
