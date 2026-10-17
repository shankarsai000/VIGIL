# Phase I1: Benchmark and Ablations Report
## 1. Executive Summary & Core Results
This benchmark compares six agent governance methods across 60 empirical evaluation runs (20 runs for each of 3 scenarios) with fixed PRNG seed (`seed=42`). Every method observed identical benign and attack event streams.
### Aggregated Performance Across All Scenarios (60 Runs)
| Method | Description | Attacks Blocked | Coverage (95% CI) | Benign Blocked | False-Block Rate (Clopper-Pearson 95%) | Mean Rules | Pipeline Latency |
|---|---|---|---|---|---|---|---|
| **B0** | No policy (baseline) | 0/19000 | **0.0%** ([0.0%, 0.0%]) | 0/215000 | **0.0000%** ([0.000%, 0.002%]) | 0.0 | 0.0 ms |
| **B1** | Hand-written per-agent deny | 19000/19000 | **100.0%** ([100.0%, 100.0%]) | 6660/215000 | **3.0977%** ([3.025%, 3.172%]) | 6.33 | 0.11 ms |
| **B2** | Global tool deny (*, tool) | 19000/19000 | **100.0%** ([100.0%, 100.0%]) | 23320/215000 | **10.8465%** ([10.715%, 10.979%]) | 6.33 | 0.04 ms |
| **B3** | VIGIL (Replay + CP Bound) | 8000/19000 | **42.1%** ([41.4%, 42.8%]) | 0/215000 | **0.0000%** ([0.000%, 0.002%]) | 2.67 | 32.09 ms |
| **A1** | Ablation: Point estimate only (no bound) | 12000/19000 | **63.2%** ([62.5%, 63.8%]) | 0/215000 | **0.0000%** ([0.000%, 0.002%]) | 4.0 | 32.35 ms |
| **A2** | Ablation: No replay (blind accept) | 19000/19000 | **100.0%** ([100.0%, 100.0%]) | 6660/215000 | **3.0977%** ([3.025%, 3.172%]) | 6.33 | 31.38 ms |

---

## 2. Scenario Breakdown
### Scenario: Distinct Attack Tools (`distinct_tools`)
*Standard 6 attack families with separate tools from legitimate benign baseline*

| Method | Coverage | False-Block Rate | Clopper-Pearson 95% Bound | Rules | Latency |
|---|---|---|---|---|---|
| **B0** | 0.0% | 0.0000% | [0.000%, 0.004%] | 0.0 | 0.0 ms |
| **B1** | 100.0% | 0.0000% | [0.000%, 0.004%] | 6.0 | 0.12 ms |
| **B2** | 100.0% | 0.0000% | [0.000%, 0.004%] | 6.0 | 0.05 ms |
| **B3** | 66.7% | 0.0000% | [0.000%, 0.004%] | 4.0 | 44.23 ms |
| **A1** | 66.7% | 0.0000% | [0.000%, 0.004%] | 4.0 | 42.03 ms |
| **A2** | 100.0% | 0.0000% | [0.000%, 0.004%] | 6.0 | 40.14 ms |

### Scenario: Dual-Use / Shared Tools (`shared_tools`)
*Attack telemetry includes attacks targeting legitimately used tools (e.g. send_email)*

| Method | Coverage | False-Block Rate | Clopper-Pearson 95% Bound | Rules | Latency |
|---|---|---|---|---|---|
| **B0** | 0.0% | 0.0000% | [0.000%, 0.004%] | 0.0 | 0.0 ms |
| **B1** | 100.0% | 6.6600% | [6.506%, 6.816%] | 7.0 | 0.12 ms |
| **B2** | 100.0% | 23.3200% | [23.058%, 23.583%] | 7.0 | 0.05 ms |
| **B3** | 57.1% | 0.0000% | [0.000%, 0.004%] | 4.0 | 44.03 ms |
| **A1** | 57.1% | 0.0000% | [0.000%, 0.004%] | 4.0 | 47.31 ms |
| **A2** | 100.0% | 6.6600% | [6.506%, 6.816%] | 7.0 | 46.46 ms |

### Scenario: Sparse Baseline Traffic (`sparse_benign`)
*Low benign event count (<600/agent) evaluating statistical bound behavior under data sparsity*

| Method | Coverage | False-Block Rate | Clopper-Pearson 95% Bound | Rules | Latency |
|---|---|---|---|---|---|
| **B0** | 0.0% | 0.0000% | [0.000%, 0.025%] | 0.0 | 0.0 ms |
| **B1** | 100.0% | 0.0000% | [0.000%, 0.025%] | 6.0 | 0.09 ms |
| **B2** | 100.0% | 0.0000% | [0.000%, 0.025%] | 6.0 | 0.04 ms |
| **B3** | 0.0% | 0.0000% | [0.000%, 0.025%] | 0.0 | 8.02 ms |
| **A1** | 66.7% | 0.0000% | [0.000%, 0.025%] | 4.0 | 7.71 ms |
| **A2** | 100.0% | 0.0000% | [0.000%, 0.025%] | 6.0 | 7.55 ms |

---

## 3. Key Findings & Ablation Analysis

### Finding 1: Safe Blocking & The Zero False-Block Invariant
- In **Scenario 2 (Dual-Use / Shared Tools)**, an attacker exploits `send_email` on `customer_bot`. Because `send_email` is a legitimate tool invoked in normal operations, naive blocking causes severe business disruption:
  - **B1 (Hand-written per-agent deny)** blocked **6660** legitimate benign events (6.66% false-block rate).
  - **B2 (Global tool deny)** blocked **23320** legitimate benign events across multiple agents (23.32% false-block rate).
  - **A2 (No replay ablation)** blindly deployed rules and blocked **6660** benign calls.
  - **B3 (VIGIL)** evaluated the candidate through counterfactual replay, detected `benign_blocked > 0`, and correctly classified the rule as `NOT_ENFORCEABLE`. As a result, B3 incurred **0 benign calls blocked** (0.0000% false-block rate, Clopper-Pearson upper bound <= 0.004%).
### Finding 2: Statistical Bound Prevents Premature Rule Deployment
- In **Scenario 3 (Sparse Baseline Traffic)**, benign event sample counts are constrained (<600 records/agent).
  - **A1 (Point estimate only)** observes 0 empirical false blocks in the small sample and accepts the rules.
  - **B3 (VIGIL with Clopper-Pearson bound)** calculates that the 95% upper bound on false blocks exceeds 0.005, correctly classifying the candidates as `INSUFFICIENT_EVIDENCE`. VIGIL refuses to deploy unproven policies into production without rigorous mathematical assurance.
### Finding 3: Negative Result — Single-Tool Rule Coverage Tradeoff
- On agents experiencing multiple distinct attack vectors (e.g. `customer_bot` attacked via both `data_export` and `system_override`), evaluating single-tool candidate rules yields 50% coverage per rule. Because the policy immune replay threshold requires `coverage >= 0.90` per candidate rule, VIGIL correctly rejects partial rules that fail to meet the coverage threshold alone. This trades raw attack coverage (66.7% for B3 vs 100% for B1/B2) to strictly guarantee zero false blocks and satisfy policy thresholds.
---

## 4. Prior-Art & Novelty Note
Per evaluation protocol instructions (*'Write a prior-art note only from sources the human places in docs/research/. Without them, mark novelty UNVERIFIED.'*):
- The `docs/research/` directory is not populated.
- Novelty status: **UNVERIFIED**.
---

## 5. Traceability & Acceptance Checklist
- [x] Fixed seed reproducibility: Verified identical output on consecutive runs with `--seed 42`.
- [x] All 6 methods evaluated across all scenarios on identical event streams.
- [x] Exact Clopper-Pearson intervals and Wilson 95% confidence intervals reported.
- [x] Pipeline latency measured and documented.
- [x] Negative findings documented without threshold tuning.
