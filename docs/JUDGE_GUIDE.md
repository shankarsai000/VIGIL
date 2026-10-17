# VIGIL 2.0 — Judge & Evaluator Reproduction Guide (5-Minute Path)

Welcome to the **VIGIL 2.0** verification guide for the ArmorIQ Flow State Hackathon. This document provides an exact, self-contained, 5-minute path to verify every requirement, peak innovation, live platform receipt, and benchmark claim.

---

## 30-Second Summary

**VIGIL 2.0** is an enterprise policy-immune AI agent governance platform native to **ArmorIQ (`armoriq-sdk==0.6.10`)**.
- **The Core Problem**: Autonomous agents with tool execution privileges risk catastrophic compromise (prompt injection, privilege escalation, unauthorized delegation). Traditional heuristic blocking disrupts normal business operations (false blocks).
- **The VIGIL Solution**: An empirical **Policy Immune System** that evaluates synthesized OPA policies counterfactually against historical agent traces using exact **one-sided Clopper-Pearson statistical bounds**. A policy is deployed live via ArmorIQ if and only if it is proven to incur zero false blocks.
- **Strict Invariant**: **Only ArmorIQ blocks agent tool calls.** No client-side pre-checks are permitted.

---

## 5-Minute Verification Runbook

All commands can be run with `uv run python` or `.venv\Scripts\python.exe` (Windows PowerShell / POSIX).

### Step 1: Automated Requirements Compliance Audit (~2 seconds)
Verify that all brief requirements and deliverables are verified with evidence on disk:
```bash
uv run python scripts/check_requirements.py
```
**Expected Output:**
```text
====================================================================
VIGIL 2.0 -- REQUIREMENTS COMPLIANCE CHECKER
Mode: BASELINE AUDIT
====================================================================
Item Count: 25
  PASS           : 22
  IN PROGRESS    : 1
  NOT STARTED    : 2
  BLOCKED        : 0
  FAIL           : 0
...
VERIFICATION: PASS
```

---

### Step 2: Peak Innovation — Explainable Denials & Provenance API (~15 seconds)
Verify Feature B: Every ArmorIQ tool denial links to its approved proposal, coverage, and statistical false-block bound with zero invented provenance:
```bash
uv run pytest backend/tests/test_explainable_denials.py -v
```
**Expected Output:**
```text
backend/tests/test_explainable_denials.py::test_planted_denial_no_proposal_returns_source_unknown PASSED
backend/tests/test_explainable_denials.py::test_denial_with_approved_proposal_returns_provenance PASSED
backend/tests/test_explainable_denials.py::test_unapproved_proposal_does_not_label_denial_as_policy_driven PASSED
backend/tests/test_explainable_denials.py::test_nonexistent_trace_returns_source_unknown PASSED
============================== 4 passed in ~16s ==============================
```

---

### Step 3: Peak Innovation — Reproduce the Empirical Benchmark (~30 seconds)
Run the benchmark across 60 empirical runs (20 runs across 3 scenarios: Distinct Tools, Dual-Use Shared Tools, Sparse Baseline Traffic) comparing B0, B1, B2, B3, A1, and A2:
```bash
uv run python bench/benchmark.py --seed 42 --runs 20
```
**Expected Output:**
- Completes in ~30 seconds over 215,000 benign events and 19,000 attack events.
- Writes detailed JSON data to `evidence/I1/results.json`.
- Writes formatted report to `evidence/I1/results.md`.
- **Key Result**: B3 (VIGIL) achieves **0.0000%** false blocks ([0.000%, 0.002%] Clopper-Pearson bound) while naive B1, B2, and A2 cause **3.10% to 10.85%** false blocks on business workflows.

---

### Step 4: Verify Bit-for-Bit Reproducibility & Number Traceability (~35 seconds)
Prove that the benchmark produces 100% identical mathematical outputs across consecutive runs and that all markdown figures trace to JSON:
```bash
uv run python bench/verify_benchmark.py
```
**Expected Output:**
```text
[Verify] Testing reproducibility across two consecutive runs with seed=42...
[PASS] Exact reproducibility verified: All mathematical metrics are 100% bit-for-bit identical.
[Verify] Testing traceability of numbers in evidence/I1/results.md against results.json...
[PASS] Traceability verified: all aggregated metrics trace directly to results.json.

[Verify] All Phase I1 benchmark verification checks PASSED!
```

---

### Step 5: Run Full Test Suite (~25 seconds)
Run the automated test suite covering all gates, replay engine, compiler, ledger, and signatures:
```bash
uv run pytest backend/tests/
```
**Expected Output:**
```text
============================== 45 passed in ~28s ==============================
```

---

## Where to Look in the ArmorIQ Platform Dashboard

1. **Active MCP Registrations (`Catalog / MCP Servers`)**:
   - Verify `vigil-tools` (agent business tools: `order_status`, `billing_database`).
   - Verify `vigil-containment` (containment tools: `quarantine_agent`, `release_agent`).
   - Onboarding manifest: [`evidence/R2/mcp_list.json`](file:///d:/vigil-v2/vigil-v2/evidence/R2/mcp_list.json).

2. **Policy Evaluation & Decisions (`Audit / Policy Decisions`)**:
   - **OPA Deny Log**: Notice policy blocks for `billing_database` when called outside approved plans.
     - Exception: `PolicyBlockedException: Tool 'billing_database' denied by OPA: policy_constraints_not_satisfied`.
     - Evidence: [`evidence/P1/mint_probe.json`](file:///d:/vigil-v2/vigil-v2/evidence/P1/mint_probe.json), [`evidence/R2/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/R2/live_receipt.json).
   - **Signed Intent Tokens**: Observe valid intent tokens minted via `client.get_intent_token(...)` (e.g., token ID `7ea57cebab814e5ab738434378d67746`).

3. **Approval Holds (`Approvals / Governance`)**:
   - High-impact operations trigger `PolicyHoldException` requiring operator confirmation via Slack gateway.
   - Evidence: [`evidence/M5/live_verification.json`](file:///d:/vigil-v2/vigil-v2/evidence/M5/live_verification.json).

4. **Cryptographic Ed25519 Receipts**:
   - Inspect offline-verifiable receipts signed with Ed25519 in [`evidence/R2/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/R2/live_receipt.json).

### Step 6: V3 Demo Scenarios — Confused Deputy & Low-and-Slow (~5 seconds)
Execute the real multi-agent pipeline demonstration scenarios offline:
```bash
uv run python scripts/scenario_confused_deputy.py
uv run python scripts/scenario_low_and_slow.py
```
**Expected Output:**
- Scenario 5: Confused Deputy delegation detected via DIFC taint (`EXTERNAL_UNTRUSTED`), local detector score 0.0, blocked by ArmorIQ (`POLICY_BLOCKED`).
- Scenario 6: Low-and-slow exfiltration trips sliding budget at chunk 5 (cumulative 10,240 bytes), canary trips at chunk 24, antibody synthesized in 0.0331s.

---

### Step 7: V3 Empirical Ablations Suite (E0 through E5) (~4 seconds)
Run the full v3 ablation suite reproducing the 1,080-scenario benchmark across all 6 scenario families:
```bash
uv run python bench/v3/run_ablations.py --seed 42
```
**Expected Output:**
- Evaluates E0 (0% detection) -> E1 (25%) -> E2 (50%) -> E3 (50%) -> E4 (100%) -> E5 (100%).
- 0 false blocks across 1,000 benign events (one-sided 95% bound: 0.299%).
- Writes `evidence/V9/results.json` and `evidence/V9/results.md`.

---

## Primary Innovation Index

| Innovation | Key Claim | Evidence File | Status |
|---|---|---|---|
| **Explainable Denials** | Deterministic mapping from denial to approved proposal and replay bound | [`evidence/P1/report.md`](file:///d:/vigil-v2/vigil-v2/evidence/P1/report.md) | **MEASURED-OFFLINE** |
| **Plan Vetting Live Probe** | ArmorIQ evaluates policies at invoke, not mint (documented negative finding) | [`evidence/P1/mint_probe.json`](file:///d:/vigil-v2/vigil-v2/evidence/P1/mint_probe.json) | **NEGATIVE** |
| **Policy Immune Replay** | Clopper-Pearson bound guarantees 0.0000% false blocks vs 3.10%–10.85% naive | [`evidence/I1/results.md`](file:///d:/vigil-v2/vigil-v2/evidence/I1/results.md) | **MEASURED-OFFLINE** |
| **Dual-MCP Containment** | Governed isolation over real ArmorIQ proxy (`customer-proxy.armoriq.ai`) | [`evidence/R2/live_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/R2/live_receipt.json) | **MEASURED-LIVE** |
| **DIFC Multi-Hop Lineage (V1)** | Monotonic taint propagation catches confused deputy delegations without client-side blocking | [`evidence/V1/live_taint_enforcement.json`](file:///d:/vigil-v2/vigil-v2/evidence/V1/live_taint_enforcement.json) | **MEASURED-LIVE** |
| **Sliding Budgets & Canaries (V3)** | Sliding 1m/1h ledgers and decoy canaries catch low-and-slow exfiltration | [`evidence/V3/benchmark.json`](file:///d:/vigil-v2/vigil-v2/evidence/V3/benchmark.json) | **MEASURED-OFFLINE** |
| **Scanning & Schema Pinning (V4)** | Deterministic role-marker scanning and canonical SHA-256 schema pinning | [`evidence/V4/output_scanning_evaluation.json`](file:///d:/vigil-v2/vigil-v2/evidence/V4/output_scanning_evaluation.json) | **MEASURED-OFFLINE** |
| **Antibody Synthesis (V5)** | Automated candidate rule generation backtested across 500 benign events in 0.0331s | [`evidence/V5/candidate_backtest.json`](file:///d:/vigil-v2/vigil-v2/evidence/V5/candidate_backtest.json) | **MEASURED-OFFLINE** |
| **Compensating Rollback (V6)** | Reverse Saga execution restores pre-state SHA-256 hashes for state mutations | [`evidence/V6/rollback_receipt.json`](file:///d:/vigil-v2/vigil-v2/evidence/V6/rollback_receipt.json) | **MEASURED-OFFLINE** |

---

## Honest Account of Limitations

1. **Invoke-Time Policy Evaluation**: ArmorIQ evaluates inline deny rules at tool invocation rather than token minting time. In compliance with platform invariants, no client-side tool pre-checks are implemented.
2. **Proxy Network Overhead**: Governed out-of-band actuation through proxy tunnels incurs 3.5s–4.5s latency (acceptable for containment, but high for micro-queries).
3. **Multi-Vector Attack Coverage Tradeoff**: When an agent experiences simultaneous attacks across multiple tools, single-tool rules cover only a fraction of attacks (50%), which VIGIL intentionally rejects to prioritize operational continuity over aggressive blocking.
4. **Irreversible Real-World Operations**: External out-of-band operations (e.g. dispatched emails, wire transfers) cannot be rolled back via software compensations and are cataloged as `IRREVERSIBLE`.
5. **Novelty Literature**: Without verified external sources in `docs/research/`, prior-art novelty is conservatively designated as **UNVERIFIED**.

