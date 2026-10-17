# Phase V8 Final Report: Real Pipeline Demo Scenarios 5 & 6

## Summary
Phase V8 executes and proves two complex multi-agent security demonstration scenarios against the real VIGIL v3 pipeline:
1. **Scenario 5 (Confused Deputy Multi-Hop Delegation)**: CustomerBot ingests an indirect prompt injection via support ticket #8821, delegating to AnalyticsAgent, which orders BillingAgent to invoke `billing_database`. Because BillingAgent is authorized to call `billing_database`, its local detector score is 0.0. However, VIGIL's Decentralized Information Flow Control (DIFC) tracks multi-hop taint propagation to `EXTERNAL_UNTRUSTED`, attaching an inline deny policy for ArmorIQ. ArmorIQ enforces the block with `PolicyBlockedException` (`POLICY_BLOCKED`, `ARMORIQ_ENFORCED`).
2. **Scenario 6 (Low-and-Slow Exfiltration, Canary Tripwire & Antibody Synthesis)**: AnalyticsAgent extracts database records in 2,048-byte chunks, evading single-call thresholds. The sliding window budget ledger triggers at chunk 5 (cumulative 10,240 bytes $\ge$ 10,240 bytes 1-minute window ceiling), selecting `DOWNGRADE_SCOPE`. At chunk 24, an HMAC-derived canary token (`canary_token_0`) trips, escalating containment to `QUARANTINE_ROLLBACK`. The pipeline synthesizes a candidate antibody rule and proves it across 500 benign trials with 0 false blocks (one-sided 95% Clopper-Pearson bound 0.005974, recall 1.0) in a measured 0.0331 seconds—90.6x faster than the 3.0 seconds claimed in the proposal.

---

## Acceptance Table

| Item | Requirement / Step | Status | Evidence Path |
|---|---|---|---|
| **V8-01** | Scenario 5 runs through real monitor and lineage, records un-manipulated detector score (0.0) | **PASS** | [`scripts/scenario_confused_deputy.py:L100-L109`](file:///d:/vigil-v2/vigil-v2/scripts/scenario_confused_deputy.py#L100-L109), [`evidence/V8/scenario_5.json:L26`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_5.json#L26) |
| **V8-02** | Scenario 5 lineage taint (`EXTERNAL_UNTRUSTED`) and ArmorIQ decision recorded with trace ID | **PASS** | [`evidence/V8/scenario_5.json:L5-L27`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_5.json#L5-L27) |
| **V8-03** | Scenario 6 extracts 2KB chunks through sliding window budget ledger and canary table | **PASS** | [`scripts/scenario_low_and_slow.py:L60-L85`](file:///d:/vigil-v2/vigil-v2/scripts/scenario_low_and_slow.py#L60-L85), [`evidence/V8/scenario_6.json:L8-L12`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_6.json#L8-L12) |
| **V8-04** | Scenario 6 records chunk of first alert (chunk 5), containment tier (`DOWNGRADE_SCOPE`), and canary hit (chunk 24) | **PASS** | [`evidence/V8/scenario_6.json:L13-L24`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_6.json#L13-L24) |
| **V8-05** | Time from first alert to synthesized & backtested candidate measured and compared with 3s proposal claim | **PASS** | [`scripts/scenario_low_and_slow.py:L110-L165`](file:///d:/vigil-v2/vigil-v2/scripts/scenario_low_and_slow.py#L110-L165), [`evidence/V8/scenario_6.json:L25-L38`](file:///d:/vigil-v2/vigil-v2/evidence/V8/scenario_6.json#L25-L38) |
| **V8-06** | Scripts `scenario_confused_deputy.py` and `scenario_low_and_slow.py` support `--offline` flag | **PASS** | [`scripts/scenario_confused_deputy.py:L221-L229`](file:///d:/vigil-v2/vigil-v2/scripts/scenario_confused_deputy.py#L221-L229), [`scripts/scenario_low_and_slow.py:L211-L217`](file:///d:/vigil-v2/vigil-v2/scripts/scenario_low_and_slow.py#L211-L217) |
| **V8-07** | `docs/DEMO_SCRIPT.md` updated with steps and all numbers marked "from evidence" | **PASS** | [`docs/DEMO_SCRIPT.md:L58-L85`](file:///d:/vigil-v2/vigil-v2/docs/DEMO_SCRIPT.md#L58-L85) |
| **V8-08** | Automated test verifies every number in demo script appears in an evidence file | **PASS** | [`backend/tests/test_demo_scenarios.py:L57-L121`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_demo_scenarios.py#L57-L121) |
| **V8-09** | Static decision boundary AST test passes | **PASS** | [`backend/tests/test_static_tool_decision_boundary.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_static_tool_decision_boundary.py) |

---

## Files Added or Modified

| File | Change | Lines | Rationale |
|---|---|---|---|
| `scripts/scenario_confused_deputy.py` | Added | 230 | End-to-end multi-hop delegation scenario measuring pipeline detector score and DIFC taint |
| `scripts/scenario_low_and_slow.py` | Added | 218 | Low-and-slow budget extraction, canary tripwire, and antibody synthesis time measurement |
| `evidence/V8/scenario_5.json` | Added | 45 | Official execution receipt for Scenario 5 |
| `evidence/V8/scenario_6.json` | Added | 39 | Official execution receipt for Scenario 6 |
| `docs/DEMO_SCRIPT.md` | Modified | +28 | Walkthrough steps for Scenarios 5 & 6 with exact evidence citations |
| `backend/tests/test_demo_scenarios.py` | Added | 122 | Pytest suite validating end-to-end runs and checking all demo numbers against evidence |
| `evidence/V8/report.md` | Added | 56 | Phase V8 compliance report |

---

## What is Not Verified and Why
- Live production network execution for every single test invocation: The test suite defaults to offline simulated proxy evaluation to avoid external service flakiness during CI; live verification against `customer-proxy.armoriq.ai` was executed in Phase V1 and is supported via the `--live` flag.

---

## Blockers for Next Phase
- None. Phase V8 acceptance criteria are fully satisfied. Ready to proceed to Phase V9 (`v9-benchmarks`).
