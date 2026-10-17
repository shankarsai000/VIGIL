# Phase V3 Final Report: Low-and-Slow Budgets and Canary Tripwires

## Summary
Phase V3 implements detection and containment for low-and-slow data exfiltration attacks that evade single-event anomaly detection. Using sliding-window exfiltration budgets (1-minute, 1-hour, and session lifetimes) combined with Shannon entropy estimation and HMAC-derived decoy canary tripwires, VIGIL identifies sub-threshold leakage early in an exfiltration campaign. In compliance with privacy and data protection invariants, only numeric aggregates (byte counts, record counts, and entropy) are persisted; raw payload text is never recorded.

---

## Acceptance Table

| Item | Requirement / Step | Status | Evidence Path |
|---|---|---|---|
| **V3-01** | Sliding window budget ledger implementation | **PASS** | [`backend/app/budgets/ledger.py`](file:///d:/vigil-v2/vigil-v2/backend/app/budgets/ledger.py) |
| **V3-02** | Unit test: Window roll-over pruning | **PASS** | [`backend/tests/test_budgets_and_canaries.py:L41-L67`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_budgets_and_canaries.py#L41-L67) |
| **V3-03** | Unit test: Per-trace and per-principal isolation | **PASS** | [`backend/tests/test_budgets_and_canaries.py:L70-L95`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_budgets_and_canaries.py#L70-L95) |
| **V3-04** | Unit test: Shannon entropy known-answer verification | **PASS** | [`backend/tests/test_budgets_and_canaries.py:L17-L38`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_budgets_and_canaries.py#L17-L38) |
| **V3-05** | Privacy test: Proves zero raw content stored in ledger | **PASS** | [`backend/tests/test_budgets_and_canaries.py:L98-L117`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_budgets_and_canaries.py#L98-L117) |
| **V3-06** | Canary tripwire layer (table access & outbound token leak) | **PASS** | [`backend/app/budgets/canary.py`](file:///d:/vigil-v2/vigil-v2/backend/app/budgets/canary.py), [`backend/tests/test_budgets_and_canaries.py:L120-L144`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_budgets_and_canaries.py#L120-L144) |
| **V3-07** | Benign dataset calibration record (train split) | **PASS** | [`evidence/V3/calibration.json`](file:///d:/vigil-v2/vigil-v2/evidence/V3/calibration.json) |
| **V3-08** | Benchmark execution (250 chunks x 2 KB, 3 detectors) | **PASS** | [`bench/v3/benchmark_low_and_slow.py`](file:///d:/vigil-v2/vigil-v2/bench/v3/benchmark_low_and_slow.py), [`evidence/V3/benchmark.json`](file:///d:/vigil-v2/vigil-v2/evidence/V3/benchmark.json) |
| **V3-09** | Static decision boundary AST test | **PASS** | [`backend/tests/test_static_tool_decision_boundary.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_static_tool_decision_boundary.py) |

---

## Benchmark Findings: Comparison of Detectors

Simulating a 250-chunk exfiltration attack (~2 KB per chunk, total 512,000 bytes):

1. **Sliding Window Budget Ledger**:
   - First Alert: **Chunk 4** (cumulative 10,240 bytes in 1-minute window).
   - Containment Tier Selected: `DOWNGRADE_SCOPE`.
2. **Canary Tripwire**:
   - First Alert: **Chunk 24** (canary token exfiltration in outbound arguments).
   - Containment Tier Selected: `QUARANTINE_ROLLBACK`.
3. **EWMA Single-Event Detector Alone**:
   - First Alert: **Chunk 210** (late alert via frequency drift).
   - Finding: EWMA alone fails to alert during early exfiltration because individual 2 KB payloads stay below the per-request anomaly score threshold (0.45).
4. **Benign Test Split Statistical Rigor**:
   - Trials: 500 benign events.
   - Observed False Trips: 0.
   - Statistically Rigorous Bound: **0 of 500; one-sided 95% upper bound from Clopper-Pearson is 0.597%**.

---

## Files Added or Modified

| File | Change | Lines | Rationale |
|---|---|---|---|
| `backend/app/budgets/__init__.py` | Added | 6 | Exported public budget and canary interfaces |
| `backend/app/budgets/ledger.py` | Added | 235 | Sliding window ledger, Shannon entropy calculator, and aggregate-only storage |
| `backend/app/budgets/canary.py` | Added | 125 | HMAC canary token generator and SQL/payload tripwire detector |
| `backend/tests/test_budgets_and_canaries.py` | Added | 145 | Unit tests covering entropy, roll-over, trace isolation, privacy, and canary hits |
| `bench/v3/benchmark_low_and_slow.py` | Added | 225 | Reproducible benchmark and calibration runner for low-and-slow exfiltration |
| `evidence/V3/calibration.json` | Added | 20 | Train-split calibration metrics and threshold baseline |
| `evidence/V3/benchmark.json` | Added | 35 | Benchmark comparison metrics across EWMA, budget, and canary detectors |
| `evidence/V3/report.md` | Added | 56 | Phase V3 compliance report |

---

## What is Not Verified and Why
- None. All acceptance tests and benchmarks passed offline from a deterministic fixed seed (seed=42).

---

## Blockers for Next Phase
- None. Phase V3 acceptance criteria are satisfied. Ready to proceed to Phase V4 (`v4-scanning`).
