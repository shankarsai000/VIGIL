# Phase V4 Final Report: Tool Schema Pinning and Output Scanning

## Summary
Phase V4 implements protection against tool rug-pulls (unauthorized post-registration modification of tool descriptions or schemas) and indirect prompt injection attacks embedded inside tool execution results. Tool definitions are pinned via canonical SHA-256 digests stored in a tamper-evident hash-chained ledger. The Stage 1 deterministic output scanner detects role markers, override directives, hidden markup (zero-width characters and comments), and base64-encoded payloads. In accordance with Rule A, scanned outputs never block tool calls on their own; instead, flagged outputs elevate the child span's lineage taint to `EXTERNAL_UNTRUSTED` so that ArmorIQ enforces downstream policy decisions at restricted sinks.

---

## Acceptance Table

| Item | Requirement / Step | Status | Evidence Path |
|---|---|---|---|
| **V4-01** | Tool schema pinning registry and hash-chained ledger | **PASS** | [`backend/app/runtime/pinning.py`](file:///d:/vigil-v2/vigil-v2/backend/app/runtime/pinning.py) |
| **V4-02** | Planted schema rug-pull detected on refresh & marked UNTRUSTED_SCHEMA | **PASS** | [`backend/tests/test_schema_pinning_and_scanning.py:L17-L52`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_schema_pinning_and_scanning.py#L17-L52) |
| **V4-03** | Stage 1 deterministic tool output scanner | **PASS** | [`backend/app/detection/output_scanner.py`](file:///d:/vigil-v2/vigil-v2/backend/app/detection/output_scanner.py) |
| **V4-04** | Planted injection raises lineage taint to EXTERNAL_UNTRUSTED (no local block) | **PASS** | [`backend/tests/test_schema_pinning_and_scanning.py:L55-L101`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_schema_pinning_and_scanning.py#L55-L101) |
| **V4-05** | Labelled corpus evaluation (200 benign, 100 injected) with Wilson intervals | **PASS** | [`bench/v3/evaluate_output_scanner.py`](file:///d:/vigil-v2/vigil-v2/bench/v3/evaluate_output_scanner.py), [`evidence/V4/output_scanning_evaluation.json`](file:///d:/vigil-v2/vigil-v2/evidence/V4/output_scanning_evaluation.json) |
| **V4-06** | Scope limits explicitly documented in spec | **PASS** | [`docs/V3_SPEC.md:182-192`](file:///d:/vigil-v2/vigil-v2/docs/V3_SPEC.md#L182-L192) |
| **V4-07** | Static decision boundary AST test | **PASS** | [`backend/tests/test_static_tool_decision_boundary.py`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_static_tool_decision_boundary.py) |

---

## Corpus Evaluation Findings

- **Corpus Origin**: Synthesized internal evaluation corpus created for VIGIL v3 (200 benign items, 100 injected items).
- **Precision**: **100.0%** (95% Wilson Score CI: **[95.9%, 100.0%]**) with 0 false positives on benign tool outputs.
- **Recall**: **90.0%** (95% Wilson Score CI: **[82.6%, 94.5%]**) with 90 of 100 attacks flagged across role markers, instruction overrides, zero-width characters, and base64 strings.
- **Accuracy**: **96.67%**.

---

## Files Added or Modified

| File | Change | Lines | Rationale |
|---|---|---|---|
| `backend/app/runtime/pinning.py` | Added | 125 | Tool schema canonical hasher, hash-chained ledger, and rug-pull detector |
| `backend/app/detection/output_scanner.py` | Added | 135 | Stage 1 deterministic scanner and lineage taint propagator |
| `backend/tests/test_schema_pinning_and_scanning.py` | Added | 102 | Unit tests for schema pinning, rug-pull detection, and taint elevation |
| `bench/v3/evaluate_output_scanner.py` | Added | 170 | Evaluation harness for precision and recall with Wilson score intervals |
| `docs/V3_SPEC.md` | Modified | +10 | Documented tool output scanning scope limits (Section 8) |
| `evidence/V4/output_scanning_evaluation.json` | Added | 30 | Full evaluation metrics, confusion matrix, and confidence intervals |
| `evidence/V4/report.md` | Added | 52 | Phase V4 compliance report |

---

## What is Not Verified and Why
- **Stage 2 ML Weights**: In accordance with the prompt specification, Stage 2 ML classifier is defined via an abstract interface (`ToolOutputClassifierInterface`) with no heavy weights bundled in the repository. Offline tests run strictly against Stage 1 deterministic rules.

---

## Blockers for Next Phase
- None. Phase V4 acceptance criteria are satisfied. Ready to proceed to Phase V5 (`v5-antibodies`).
