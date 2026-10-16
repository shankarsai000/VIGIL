# Phase M2: Replay Engine and the False-Block Bound Report

## 1. Acceptance Table

| Item / Acceptance Criterion | Description | Status | Exact Evidence File & Line |
|---|---|---|---|
| **Build Item 1** | `backend/app/immune/replay.py`: `CandidateRule(agent_id, mcp_id, tool)` denying one tool for one agent | PASS | [`backend/app/immune/replay.py:21-29`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/replay.py#L21-L29) |
| **Build Item 2** | Metrics calculation: `attacks_total`, `attacks_blocked`, `coverage`, `benign_total`, `benign_blocked`, `false_block_point` | PASS | [`backend/app/immune/replay.py:117-142`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/replay.py#L117-L142) |
| **Build Item 3** | Exact Clopper-Pearson one-sided bound: `scipy.stats.beta.ppf(1 - delta, benign_blocked + 1, benign_total - benign_blocked)` with $\delta = 0.05$ | PASS | [`backend/app/immune/replay.py:68-87`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/replay.py#L68-L87)<br>[`backend/tests/test_immune_replay.py:20-41`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_replay.py#L20-L41) |
| **Build Item 4** | Status decision logic:<br>• `ACCEPT` if `coverage >= 0.90`, `false_block_upper <= 0.005`, `benign_total >= 600`, and `attacks_total >= 3`<br>• `INSUFFICIENT_EVIDENCE` if a sample threshold fails<br>• `REJECT` if coverage or the bound fails with enough data | PASS | [`backend/app/immune/replay.py:151-157`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/replay.py#L151-L157)<br>[`backend/tests/test_immune_replay.py:136-180`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_replay.py#L136-L180) |
| **Build Item 5** | Output `ReplayReport` as JSON with assumptions block: exchangeability, assumed benign labels, window bounds | PASS | [`backend/app/immune/replay.py:31-65`](file:///d:/vigil-v2/vigil-v2/backend/app/immune/replay.py#L31-L65)<br>[`evidence/M2/replay_report_accept.json:1-26`](file:///d:/vigil-v2/vigil-v2/evidence/M2/replay_report_accept.json#L1-L26)<br>[`evidence/M2/replay_report_sample.json:1-26`](file:///d:/vigil-v2/vigil-v2/evidence/M2/replay_report_sample.json#L1-L26) |
| **Build Item 6** | Add `scipy` to `backend/requirements.txt` | PASS | [`backend/requirements.txt:13`](file:///d:/vigil-v2/vigil-v2/backend/requirements.txt#L13) |
| **Acceptance 1** | Known-answer tests on a fixture with hand-computed counts (ACCEPT, REJECT coverage, REJECT false-block, INSUFFICIENT_EVIDENCE sample sizes) | PASS | [`backend/tests/test_immune_replay.py:71-180`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_replay.py#L71-L180)<br>[`evidence/M2/backend_tests_offline.txt:23-28`](file:///d:/vigil-v2/vigil-v2/evidence/M2/backend_tests_offline.txt) |
| **Acceptance 2** | With zero benign blocks and `benign_total = 600`, `false_block_upper` equals $1 - 0.05^{1/600}$ within $10^{-9}$ | PASS | [`backend/tests/test_immune_replay.py:20-41`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_replay.py#L20-L41)<br>*(Computed: `0.0049804433803613`, Analytic: `0.0049804433803613`, $\Delta = 4.77 \times 10^{-17} < 10^{-9}$)* |
| **Acceptance 3** | Bound monotonicity verified:<br>• For fixed `benign_total`, bound never decreases as `benign_blocked` grows<br>• For fixed `benign_blocked`, bound never increases as `benign_total` grows | PASS | [`backend/tests/test_immune_replay.py:43-69`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_replay.py#L43-L69)<br>[`evidence/M2/backend_tests_offline.txt:24-25`](file:///d:/vigil-v2/vigil-v2/evidence/M2/backend_tests_offline.txt) |
| **Acceptance 4** | Test enforces that the replay module imports no network or database code (AST purity verification) | PASS | [`backend/tests/test_immune_replay.py:183-215`](file:///d:/vigil-v2/vigil-v2/backend/tests/test_immune_replay.py#L183-L215)<br>[`evidence/M2/backend_tests_offline.txt:27`](file:///d:/vigil-v2/vigil-v2/evidence/M2/backend_tests_offline.txt) |
| **Stop Rule** | If the bound cannot be reproduced from the stated formula, stop. Do not change the formula to make a test pass. | PASS | Exact analytical reproduction confirmed with absolute error $4.77 \times 10^{-17}$, zero formula alterations. |

---

## 2. Files Added or Modified

| File | Change Type | Line Count | Reason |
|---|---|---|---|
| `backend/requirements.txt` | Modified | +1 | Added `scipy>=1.13.0` dependency for Beta distribution percentile point function (`scipy.stats.beta.ppf`). |
| `backend/app/immune/replay.py` | Added | 183 | Pure counterfactual replay engine: `CandidateRule`, `ReplayAssumptions`, `ReplayReport`, `ReplayEngine`, and `compute_false_block_upper`. |
| `backend/app/immune/__init__.py` | Modified | +7 | Exported replay engine symbols (`CandidateRule`, `ReplayReport`, `ReplayEngine`, `compute_false_block_upper`, `evaluate_candidate_rule`). |
| `backend/tests/test_immune_replay.py` | Added | 241 | Comprehensive offline acceptance tests covering Clopper-Pearson exact bound, monotonicity, AST isolation, and hand-computed fixtures. |
| `evidence/M2/backend_tests_offline.txt` | Added | 84 | Test run output verifying all 79 backend offline tests passing (3 deselected live). |
| `evidence/M2/replay_report_accept.json` | Added | 26 | Sample evaluated `ReplayReport` JSON artifact demonstrating `ACCEPT` status with assumption block. |
| `evidence/M2/replay_report_sample.json` | Added | 26 | Sample evaluated `ReplayReport` JSON artifact demonstrating `INSUFFICIENT_EVIDENCE` status. |
| `evidence/M2/report.md` | Added | ~65 | Phase M2 acceptance and verification report. |

---

## 3. What is Not Verified and Why

1. **Remote ArmorIQ Cloud Gateway Live Tunnel**:
   - As per standing instructions and previous phases, live SSE tunnel tests against external endpoints (`https://armoriq.mywire.org`) remain deselected (`-m "not live"`). Offline gate and replay functionality are 100% verified locally.
2. **Online / Streaming Replay**:
   - Phase M2 strictly specifies a pure, offline replay engine with zero database reads/writes and zero network calls. End-to-end integration with the policy synthesis loop is deferred to subsequent milestones (M3/M4).

---

## 4. Blockers for Next Phase

- **None**: All M2 requirements and offline acceptance tests pass (79/79 backend tests, 25/25 frontend tests). The engine is strictly isolated from network and database code, and the Clopper-Pearson statistical bound holds to machine precision.
