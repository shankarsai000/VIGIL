# Phase V6 Final Report: Compensating Rollback and Blast Radius DAG

## Summary
Phase V6 implements compensating transactional rollback for AI agent mutations and a DAG visualization of an incident's blast radius. Tools declare inverse operations, argument mappings, and pre-state requirements in `config/tool_compensations.yaml`. Any tool without a declared inverse (such as external emails, wire transfers, and terminal commands) is strictly classified as `IRREVERSIBLE`. During graduated containment escalation to `QUARANTINE_ROLLBACK`, `rollback_session` traverses captured pre-state checkpoints in reverse chronological order, executes ArmorIQ gate-authorized compensations against the sandbox database, and restores records to their verified pre-mutation hashes. Failed compensations mark the session status as `PARTIAL` without looping.

---

## Acceptance Table

| Item | Requirement / Step | Status | Evidence Path |
|---|---|---|---|
| **V6-01** | Tool compensations catalog with inverse tools and irreversible reasons | **PASS** | [`config/tool_compensations.yaml`](file:///d:/vigil-v2/vigil-v2/config/tool_compensations.yaml) |
| **V6-02** | Pre-state checkpointing with deterministic SHA-256 state hashing | **PASS** | [`backend/app/runtime/rollback.py:L40-L75`](file:///d:/vigil-v2/vigil-v2/backend/app/runtime/rollback.py#L40-L75) |
| **V6-03** | Backward compensating rollback restores records to pre-state hash | **PASS** | [`backend/tests/test_compensating_rollback.py:L26-L74`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_compensating_rollback.py#L26-L74), [`evidence/V6/rollback_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/V6/rollback_receipt.json) |
| **V6-04** | Irreversible side-effects remain explicitly marked with rationale | **PASS** | [`backend/tests/test_compensating_rollback.py:L77-L101`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_compensating_rollback.py#L77-L101) |
| **V6-05** | Failed compensations mark session status PARTIAL without looping | **PASS** | [`backend/tests/test_compensating_rollback.py:L104-L123`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_compensating_rollback.py#L104-L123) |
| **V6-06** | Gate authorization required for compensation execution | **PASS** | [`backend/tests/test_compensating_rollback.py:L126-L130`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_compensating_rollback.py#L126-L130) |
| **V6-07** | Blast radius DAG generation and GET /traces/{trace_id}/blast-radius | **PASS** | [`backend/main.py:L1228-L1234`](file:///d:/vigil-v2/vigil-v2/backend/main.py#L1228-L1234), [`backend/tests/test_compensating_rollback.py:L133-L198`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_compensating_rollback.py#L133-L198) |
| **V6-08** | Static decision boundary AST test | **PASS** | [`backend/tests/test_static_tool_decision_boundary.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_static_tool_decision_boundary.py) |

---

## Files Added or Modified

| File | Change | Lines | Rationale |
|---|---|---|---|
| `config/tool_compensations.yaml` | Added | 48 | Declarative mapping of state-changing tools, inverse operations, and irreversible boundaries |
| `backend/app/runtime/rollback.py` | Added | 265 | Checkpoint store, reverse compensating rollback engine, and blast radius DAG builder |
| `backend/app/runtime/sandbox_store.py` | Added | 95 | In-memory sandbox store supporting state mutations and inverse compensations |
| `backend/main.py` | Modified | +10 | Added `GET /traces/{trace_id}/blast-radius` endpoint |
| `backend/tests/test_compensating_rollback.py` | Added | 198 | Unit and integration tests for rollback, state hashing, partial failures, and DAG API |
| `evidence/V6/rollback_receipt.json` | Added | 59 | Verified before/after hash matching receipt and blast radius DAG output |
| `evidence/V6/report.md` | Added | 52 | Phase V6 compliance report |

---

## What is Not Verified and Why
- **External Real-World Side Effects**: In accordance with the prompt stop rules, compensating rollback does not claim to undo external out-of-band side effects (e.g. emails already delivered to third parties, external credit card charges). Such operations are classified as `IRREVERSIBLE` with documented operational rationales.

---

## Blockers for Next Phase
- None. Phase V6 acceptance criteria are satisfied. Ready to proceed to Phase V7 (`v7-ui`).
