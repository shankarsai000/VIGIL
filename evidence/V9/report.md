# Phase V9 Final Report: Benchmark and Ablations for v3 Claims

## Summary
Phase V9 establishes an empirical ablation benchmark across six scenario families and six ablation tiers (E0 through E5), evaluating 1,080 simulated agent execution traces.
The benchmark quantifies the marginal contribution of each VIGIL v3 component:
1. **E0 (EWMA and Heuristic Rules only)**: Detects single-event parameter spikes and known injection strings, but completely fails (**0.0% [0.0%, 4.6%]**) on multi-agent confused deputy, low-and-slow exfiltration, and tool schema mutations.
2. **E1 (+ DIFC Lineage Taint / V1)**: Elevates detection to **25.0% [16.8%, 35.5%]** at 3.0 events by tracking tainted delegations from external prompts and supplying ArmorIQ with inline deny policies (`OFFLINE-HARNESS`).
3. **E2 (+ Sliding Window Budgets / V3)**: Elevates detection to **50.0% [39.3%, 60.7%]** at 4.0 events by tripping on cumulative 1-minute velocity bursts (10 KB ceiling) while persisting aggregates only.
4. **E3 (+ Canary Tripwires / V3)**: Retains **50.0%** detection while accelerating escalation to `QUARANTINE_ROLLBACK` upon synthetic database token exfiltration.
5. **E4 (+ Output Scanning & Tool Schema Pinning / V4)**: Achieves **100.0% [95.4%, 100.0%]** detection at 2.5 mean events by intercepting role-marker overrides in executed tool outputs and detecting canonical SHA-256 schema hash mismatches.
6. **E5 (+ Antibody Candidates & Counterfactual Backtesting / V5)**: Retains **100.0%** attack coverage with **0 of 1,000 false blocks** on benign traffic (one-sided 95% Clopper-Pearson upper bound: **0.299%**), incurring **0.0** self-inflicted containment disruption per 1,000 benign operations.

---

## Acceptance Table

| Item | Requirement / Step | Status | Evidence Path |
|---|---|---|---|
| **V9-01** | Six scenario families implemented with fixed seed (seed=42) | **PASS** | [`bench/v3/run_ablations.py:L70-L165`](file:///d:/vigil-v2/vigil-v2/bench/v3/run_ablations.py#L70-L165), [`evidence/V9/results.json:L2-L4`](file:///d:/vigil-v2/vigil-v2/evidence/V9/results.json#L2-L4) |
| **V9-02** | Ablations E0 through E5 evaluated with progressive component activation | **PASS** | [`bench/v3/run_ablations.py:L168-L260`](file:///d:/vigil-v2/vigil-v2/bench/v3/run_ablations.py#L168-L260), [`evidence/V9/results.json:L6-L95`](file:///d:/vigil-v2/vigil-v2/evidence/V9/results.json#L6-L95) |
| **V9-03** | Bit-for-bit identical output on repeated runs with fixed seed (0 diff) | **PASS** | [`backend/tests/test_v9_benchmarks.py:L17-L23`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_v9_benchmarks.py#L17-L23) |
| **V9-04** | Statistical bounds: Wilson 95% CI on detection, Clopper-Pearson one-sided 95% bound on false blocks | **PASS** | [`bench/v3/run_ablations.py:L50-L68`](file:///d:/vigil-v2/vigil-v2/bench/v3/run_ablations.py#L50-L68), [`evidence/V9/results.md:L11-L19`](file:///d:/vigil-v2/vigil-v2/evidence/V9/results.md#L11-L19) |
| **V9-05** | Evidence artifacts generated: `evidence/V9/results.json` and `results.md` | **PASS** | [`evidence/V9/results.json`](file:///d:/vigil-v2/vigil-v2/evidence/V9/results.json), [`evidence/V9/results.md`](file:///d:/vigil-v2/vigil-v2/evidence/V9/results.md) |
| **V9-06** | Innovation Claims Register updated with all claims and valid evidence links | **PASS** | [`docs/INNOVATION.md:L7-L18`](file:///d:/vigil-v2/vigil-v2/docs/INNOVATION.md#L7-L18), [`backend/tests/test_v9_benchmarks.py:L48-L67`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_v9_benchmarks.py#L48-L67) |
| **V9-07** | Negative findings documented in register and report | **PASS** | [`docs/INNOVATION.md:L18-L26`](file:///d:/vigil-v2/vigil-v2/docs/INNOVATION.md#L18-L26), [`evidence/V9/results.md:L22-L26`](file:///d:/vigil-v2/vigil-v2/evidence/V9/results.md#L22-L26) |
| **V9-08** | Static decision boundary AST test passes | **PASS** | [`backend/tests/test_static_tool_decision_boundary.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_static_tool_decision_boundary.py) |

---

## Files Added or Modified

| File | Change | Lines | Rationale |
|---|---|---|---|
| `bench/v3/run_ablations.py` | Added | 358 | Deterministic ablation runner across E0–E5 with fixture streams and markdown report generator |
| `evidence/V9/results.json` | Added | 97 | Machine-readable empirical ablation results and statistical confidence intervals |
| `evidence/V9/results.md` | Added | 32 | Generated markdown ablation comparison table |
| `docs/INNOVATION.md` | Modified | +5 | Registered Features E, F, G, H, I with MEASURED-OFFLINE statuses and links |
| `backend/tests/test_v9_benchmarks.py` | Added | 68 | Pytest suite validating reproducibility, progression, and innovation register integrity |
| `evidence/V9/report.md` | Added | 58 | Phase V9 compliance report |

---

## What is Not Verified and Why
- Live production token minting for all 1,080 synthetic ablation traces: Per specification ("ArmorIQ decisions are simulated only in the offline harness, and are labelled OFFLINE-HARNESS. They are never used as live evidence"), offline simulation was used to prevent unnecessary API rate exhaustion while maintaining reproducible statistical rigor.

---

## Blockers for Next Phase
- None. Phase V9 acceptance criteria are fully satisfied. Ready to proceed to Phase VF (`vf-submission`).
