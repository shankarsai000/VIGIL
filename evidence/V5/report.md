# Phase V5 Final Report: Antibody Candidates (Proposals Only)

## Summary
Phase V5 implements automated antibody candidate synthesis and counterfactual backtesting for recurring incident families. In accordance with Rule E, generated rules are strictly proposals: they are never deployed automatically, never evaluated as executable code, and require explicit human operator review through the M4 proposal workflow. Every candidate is validated against a Pydantic schema with extra fields rejected (`extra="forbid"`), length capped at 2,048 bytes, and forbidden unscientific phrasing ("0% false positives") explicitly blocked. Candidates reach "ready for review" status only if observed false blocks across $N=500$ benign records are exactly zero and attack recall is $\ge 90\%$.

---

## Acceptance Table

| Item | Requirement / Step | Status | Evidence Path |
|---|---|---|---|
| **V5-01** | Strict Pydantic antibody schema (`extra="forbid"`, length caps) | **PASS** | [`backend/app/immune/antibody.py`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/antibody.py) |
| **V5-02** | Schema validation & extra-field rejection tests | **PASS** | [`backend/tests/test_antibody_candidates.py:L32-L68`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_antibody_candidates.py#L32-L68) |
| **V5-03** | Rejection of forbidden phrasing ("0% false positives") | **PASS** | [`backend/tests/test_antibody_candidates.py:L70-L84`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_antibody_candidates.py#L70-L84) |
| **V5-04** | Exact known-answer math for Clopper-Pearson bounds | **PASS** | [`backend/tests/test_antibody_candidates.py:L87-L99`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_antibody_candidates.py#L87-L99) |
| **V5-05** | Readiness gate: Candidate with 1 false block is rejected | **PASS** | [`backend/tests/test_antibody_candidates.py:L102-L136`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_antibody_candidates.py#L102-L136) |
| **V5-06** | Readiness gate: Perfect candidate reaches ready for review | **PASS** | [`backend/tests/test_antibody_candidates.py:L139-L173`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_antibody_candidates.py#L139-L173) |
| **V5-07** | Prompt injection resilience test (safe handling, no eval) | **PASS** | [`backend/tests/test_antibody_candidates.py:L176-L192`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_antibody_candidates.py#L176-L192) |
| **V5-08** | Static test: Proves zero code paths auto-apply rules to armoriq.yaml | **PASS** | [`backend/tests/test_antibody_candidates.py:L195-L208`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_antibody_candidates.py#L195-L208) |
| **V5-09** | Counterfactual backtest evidence on 500 benign baseline events | **PASS** | [`evidence/V5/candidate_backtest.json`](file:///d:/vigil-v2/vigil-v2/evidence/V5/candidate_backtest.json) |

---

## Files Added or Modified

| File | Change | Lines | Rationale |
|---|---|---|---|
| `backend/app/immune/antibody.py` | Added | 175 | Candidate generator, schema parser, and counterfactual backtesting engine |
| `backend/tests/test_antibody_candidates.py` | Added | 215 | 8 comprehensive tests covering schema, bounds, gates, injection, and static boundaries |
| `evidence/V5/candidate_backtest.json` | Added | 20 | Verified counterfactual backtest result proving 0 false blocks in 500 benign events |
| `evidence/V5/report.md` | Added | 48 | Phase V5 compliance report |

---

## What is Not Verified and Why
- **Live Anthropic API Calling in CI**: Offline unit and benchmark tests run deterministically using feature-based proposal generation and schema validation. When `ANTHROPIC_API_KEY` is provisioned by the operator, model-generated JSON passes through the same schema parser and backtest gate.

---

## Blockers for Next Phase
- None. Phase V5 acceptance criteria are satisfied. Ready to proceed to Phase V6 (`v6-rollback`).
