# Phase DOC-FIX-1: Make the VIGIL Guide Correct and Self-Checking

**Phase**: DOC-FIX-1  
**Branch**: `doc-fix-1`  
**Date**: 2026-10-17  
**Artifact Outputs Directory**: `evidence/DOC-FIX-1/`  
**Target Reference**: `CLAUDE.md`, `config/thresholds.yaml`, `docs/V3_SPEC.md`

---

## 1. Executive Summary

Phase DOC-FIX-1 reconciles the VIGIL master architecture guide (`CLAUDE.md`) against actual codebase implementations, live SDK introspection, and recorded empirical evidence. Every number, SDK method signature, mathematical bound, and configuration threshold in the reference guide now strictly matches the underlying code and is protected against future drift by automated static AST tests and verification scripts.

---

## 2. Fix-by-Fix Implementation Summary (In Order)

### Fix 1: Backtest Window vs Gate
- **Problem**: With $n=500$ benign trials and 0 false blocks, the one-sided 95% Clopper-Pearson upper bound is $1 - 0.05^{1/500} = 0.005974$ (0.597%), which violates the policy gate ceiling `max_false_block_upper: 0.005` (0.500%). The gate was previously failing or required raising the ceiling.
- **Resolution**:
  - Set `antibody_backtest_window: 600` in `config/thresholds.yaml` to match `min_benign_records: 600` (mathematically, $n \ge 598$ is required for $1 - 0.05^{1/n} \le 0.005$; for $n=600$, the bound is $0.004980 \le 0.005$).
  - Updated Rule E and §5.5 in `CLAUDE.md`.
  - Reran Scenario 6 (`scripts/scenario_low_and_slow.py`) across 600 benign trials. Code computes bound `0.00498` and gate result `is_ready_for_review: true` (**PASS**).
  - Updated `evidence/V8/scenario_6.json` and `evidence/V5/candidate_backtest.json`.
  - Maintained `max_false_block_upper: 0.005` unchanged.

### Fix 2: SDK Signatures (§4.1, §4.2, §4.3)
- **Problem**: §4.1 previously documented fictional parameters (`client.capture_plan(user_id, agent_id, ...)`), §4.2 lacked the real SDK layer metadata, and §4.3 listed nonexistent exception classes (`NetworkError`, `Timeout`, `SDKError`).
- **Resolution**:
  - Introspected `armoriq-sdk==0.6.10` with `inspect.signature`:
    1. `capture_plan(self, llm: str, prompt: str, plan: Optional[Dict[str, Any]] = None, metadata: Optional[Dict[str, Any]] = None) -> PlanCapture`
    2. `get_intent_token(self, plan_capture: PlanCapture, policy: Optional[Dict[str, Any]] = None, validity_seconds: float = 60.0) -> IntentToken`
    3. `invoke_with_policy(self, mcp: str, action: str, intent_token: IntentToken, params: Optional[Dict[str, Any]] = None, options: Optional[InvokeOptions] = None) -> MCPInvocationResult`
    4. `InvokeOptions(*, wait_for_approval=None, delegation_timeout_ms=None, on_hold=None, user_email=None, requester_role=None, requester_limit=None)`
  - Added AST test `backend/tests/test_sdk_signatures.py` asserting that the parameters passed by `armoriq_gate._authorize_sync` match the SDK signatures.
  - Corrected §4.2 with actual metadata returned on `PolicyBlockedException`: `metadata={'layer': 'opa'}`.
  - Replaced fictional exceptions in §4.3 with actual classes from `armoriq_sdk` (`PolicyBlockedException`, `PolicyHoldException`, `IntentTokenError`, `ArmorIQException`) and standard `httpx` network exceptions.

### Fix 3: Benchmark Counts (§8.3)
- **Problem**: §8.3 previously had an mismatched confidence interval for E0 ([0.0%, 9.5%] for $k=0$ vs $n=80$ denominator) and lacked explicit sample sizes and interval definitions.
- **Resolution**:
  - Updated `bench/v3/run_ablations.py` to record sample sizes, detection counts, and exact two-sided 95% Clopper-Pearson confidence intervals.
  - Stored full counts in `evidence/V9/results.json` and regenerated table in `evidence/V9/results.md` and `CLAUDE.md` §8.3:
    - **E0**: 0.0% [0.0%, 4.5%] ($k=0, n=80$) — matches $n=80$ denominator ($1 - 0.025^{1/80} = 0.0450$).
    - **E1**: 25.0% [16.0%, 35.9%] ($k=20, n=80$)
    - **E2**: 50.0% [38.6%, 61.4%] ($k=40, n=80$)
    - **E3**: 50.0% [38.6%, 61.4%] ($k=40, n=80$)
    - **E4**: 100.0% [95.5%, 100.0%] ($k=80, n=80$)
    - **E5**: 100.0% [95.5%, 100.0%] ($k=80, n=80$)
  - Explained total trials: 1,080 = 80 attack evaluation traces across 4 scenario families + 1,000 benign operations (500 delegations + 500 bulk reads).

### Fix 4: One Threshold Table
- **Problem**: Score thresholds (0.45, 0.65, 0.75, 0.85, 0.90, 0.92) were hardcoded across multiple modules.
- **Resolution**:
  - Centralized all score thresholds in `config/thresholds.yaml`.
  - Standardized on a single unified quarantine threshold: `0.90` (replacing legacy 0.85 and 0.92) and human escalation threshold `0.65`.
  - Created `backend/app/runtime/thresholds.py` (`SystemThresholds` loader).
  - Cleaned all hardcoded float constants across backend services, policies, and scripts.
  - Implemented static AST test `backend/tests/test_one_threshold_table.py` that fails if literal values `0.45, 0.65, 0.75, 0.85, 0.90, 0.92` appear outside `config/` and `tests/`.
  - Added `scripts/generate_guide_thresholds.py` and test `backend/tests/test_guide_consistency.py` ensuring `CLAUDE.md` §6 is generated from and matches `config/thresholds.yaml`.

### Fix 5: Dry-Run Rule (§2.1, Rule 4)
- **Problem**: Rule 4 text had drifted.
- **Resolution**:
  - Restored the rule verbatim in `CLAUDE.md`:
    > "4. **Dry-Run by Default**: Writing ArmorIQ registration YAMLs, syncing with the live platform, or quarantining agents requires an approved proposal and an explicit `--live` flag. A mock environment may quarantine or write only with output labelled `NOT ENFORCED BY ARMORIQ`."

### Fix 6: Timing Claim (§8.2)
- **Problem**: §8.2 claimed "90.6x faster" without specifying scope.
- **Resolution**:
  - Removed "90.6x faster" from `CLAUDE.md` §8.2, `docs/DEMO_SCRIPT.md`, and `evidence/V8/scenario_6.json`.
  - Explicitly defined what the measured 0.0331s covers: offline candidate deny-rule synthesis and counterfactual replay over 600 benign historical ledger records (compared to 3.0s proposal estimate).

### Fix 7: Budget Boundary
- **Problem**: Ambiguity on whether budget thresholds are inclusive (`>=` vs `>`).
- **Resolution**:
  - Clarified in `CLAUDE.md` §5.3 and §8.2 that budget threshold comparisons are inclusive (`>=`). Equality triggers a breach.
  - Scenario 6 reaches exactly 10,240 bytes at chunk 5 ($5 \times 2,048$ bytes), triggering equality ($10,240\text{B} \ge 10,240\text{B}$).
  - Added boundary test `test_budget_boundary_inclusive` in `backend/tests/test_budgets_and_canaries.py` asserting that 10,239B does not breach, while 10,240B breaches and recommends `DOWNGRADE_SCOPE`.

### Fix 8: Measured Changes
- **Problem**: The canary tripwire chunk changed between the proposal narrative and empirical execution.
- **Resolution**:
  - Recorded in `docs/V3_SPEC.md` (Claim 8 and Section 4): proposal posited canary trip at chunk 4; empirical execution in Scenario 6 measured canary hit at chunk 24 following the first budget alert at chunk 5.

### Fix 9: Run Environment Labels
- **Problem**: Guide numbers lacked clear provenance labels.
- **Resolution**:
  - Marked every metric in `CLAUDE.md` §8 as `[LIVE]` or `[OFFLINE-HARNESS]`.
  - All simulated multi-turn attacks, budget evaluations, and ablations in §8 are labeled `[OFFLINE-HARNESS]`.

### Fix 10: Containment Authentication
- **Problem**: Rule B and architecture diagrams claimed "Bearer Token Auth" for the FastMCP containment server.
- **Resolution**:
  - Inspected `backend/app/policies/containment_mcp.py`: FastMCP tools bind locally and communicate with VIGIL Core (`POST /internal/containment/...`) using HTTP header `X-Containment-Secret`, with no inbound Bearer token check.
  - Corrected `CLAUDE.md` Rule B and the architecture Mermaid diagram to state `(Shared Secret: X-Containment-Secret)`.
  - Logged complete finding in `evidence/DOC-FIX-1/containment_auth_finding.md`.

### Fix 11: Portability
- **Problem**: `CLAUDE.md` contained hardcoded `file:///d:/vigil-v2/vigil-v2/` links, a Windows root path `d:\vigil-v2\vigil-v2\`, and a personal uv path `C:\Users\shank\.local\bin\uv.exe`.
- **Resolution**:
  - Replaced all absolute links with clean repo-relative markdown paths (`backend/...`, `docs/...`, `evidence/...`).
  - Updated directory tree root to `.`
  - Replaced personal uv path with standard portable invocation commands (`uv run python <script.py>`).

### Fix 12: Evidence Check Script & CI Test
- **Problem**: Risk of documentation drifting from evidence receipts.
- **Resolution**:
  - Created `scripts/check_guide_evidence.py` to recursively verify that every evidence file referenced in `CLAUDE.md` exists and that all numeric claims in §7 and §8 appear in their referenced evidence files.
  - Integrated into pytest suite via `backend/tests/test_guide_consistency.py`.

---

## 3. Acceptance Verification Table

| Requirement / Acceptance Criterion | Verification Method | Status | Evidence / Test Location |
|---|---|---|---|
| **Fix 1: Backtest window 600 & gate pass** | Run Scenario 6 with 600 trials | **PASS** | `evidence/V8/scenario_6.json`, bound `0.004980 <= 0.005` |
| **Fix 2: Real SDK signatures & AST test** | `pytest test_sdk_signatures.py` | **PASS** | `backend/tests/test_sdk_signatures.py` (4/4 passed) |
| **Fix 3: Clopper-Pearson 95% CI & E0 fix** | `pytest test_v9_benchmarks.py` | **PASS** | `evidence/V9/results.json`, `evidence/V9/results.md` |
| **Fix 4: Centralized thresholds & static AST test** | `pytest test_one_threshold_table.py` | **PASS** | `backend/tests/test_one_threshold_table.py` (1/1 passed) |
| **Fix 5: Dry-run rule restored** | Inspect `CLAUDE.md` §2.1 Rule 4 | **PASS** | `CLAUDE.md:36` |
| **Fix 6: Timing claim 0.0331s scope** | Check `CLAUDE.md` §8.2 | **PASS** | `CLAUDE.md:308`, "90.6x faster" removed |
| **Fix 7: Inclusive budget boundary test** | `pytest test_budgets_and_canaries.py` | **PASS** | `backend/tests/test_budgets_and_canaries.py:L147-L189` |
| **Fix 8: Canary chunk change documented** | Inspect `docs/V3_SPEC.md` | **PASS** | `docs/V3_SPEC.md:33` |
| **Fix 9: Metrics labeled with environment** | Inspect `CLAUDE.md` §8 | **PASS** | All metrics marked `[OFFLINE-HARNESS]` |
| **Fix 10: Containment auth finding logged** | Inspect finding file | **PASS** | `evidence/DOC-FIX-1/containment_auth_finding.md` |
| **Fix 11: Portable repo-relative links** | Inspect `CLAUDE.md` | **PASS** | Zero `file:///` or personal paths in `CLAUDE.md` |
| **Fix 12: Evidence check script** | `python scripts/check_guide_evidence.py` | **PASS** | 0 missing files, all §7 and §8 numbers verified |
| **Acceptance: §6 generated from thresholds.yaml** | `python scripts/generate_guide_thresholds.py --check` | **PASS** | `backend/tests/test_guide_consistency.py` |
| **Acceptance: Scenario 6 & E5 benign window** | Assert `antibody_backtest_window == 600` | **PASS** | `test_guide_consistency.py::test_scenario_6_and_replay_use_same_benign_window` |

---

## 4. Test Suite Execution Results

Running the complete acceptance suite:
```powershell
uv run pytest backend/tests/test_one_threshold_table.py backend/tests/test_sdk_signatures.py backend/tests/test_demo_scenarios.py backend/tests/test_budgets_and_canaries.py backend/tests/test_v9_benchmarks.py backend/tests/test_guide_consistency.py; uv run python scripts/check_guide_evidence.py; uv run python scripts/generate_guide_thresholds.py --check
```

Output:
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\vigil-v2\vigil-v2
configfile: pytest.ini
plugins: anyio-4.15.1
collected 22 items

backend\tests\test_one_threshold_table.py .                              [  4%]
backend\tests\test_sdk_signatures.py ....                                [ 22%]
backend\tests\test_demo_scenarios.py ...                                 [ 36%]
backend\tests\test_budgets_and_canaries.py ......                        [ 63%]
backend\tests\test_v9_benchmarks.py ...                                  [ 77%]
backend\tests\test_guide_consistency.py .....                            [100%]

============================= 22 passed in 11.79s =============================
[*] Checking 7 evidence paths in CLAUDE.md...
[PASS] All evidence paths exist and all Section 7 & 8 metrics match evidence files.
[PASS] CLAUDE.md Section 6 matches config/thresholds.yaml
```

---

## 5. Stop Rules & Invariants Compliance

- **No Lowered Gates**: `max_false_block_upper: 0.005` remained strictly unchanged; the backtest trial window was appropriately sized to 600 to mathematically satisfy the bound.
- **No Threshold Tampering**: All thresholds are unified centrally in `config/thresholds.yaml` and loaded dynamically via `SystemThresholds`.
- **Zero Hardcoded Score Floats**: Verified via static AST parsing across all non-test/non-config files.
- **Evidence Integrity**: All metrics cited in `CLAUDE.md` Sections 7 and 8 are verbatim matched against JSON/TXT evidence receipts on disk.
