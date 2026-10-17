# Phase V9 Benchmark and Ablations Report

## Summary
Empirical benchmark evaluating VIGIL v3 component contributions across 6 scenario families (1,080 total trials).
The 1,080 total trials per configuration comprise 80 attack trials (20 confused deputy + 20 low-and-slow + 20 tool rug-pull + 20 injected tool output) and 1,000 benign trials (500 benign delegations + 500 benign bulk reads).
Detection rate intervals are exact two-sided 95% Clopper-Pearson confidence intervals. False block bounds are exact one-sided 95% Clopper-Pearson upper bounds.
All ArmorIQ decision blocks are strictly simulated in the offline harness (`OFFLINE-HARNESS`) without external API calls.

---

## Ablation Results Table (E0 through E5)

| Ablation | Active Components | Detection Rate (Two-Sided 95% Clopper-Pearson CI) | Events to Alert | False Blocks (One-Sided 95% Bound) | Disruption / 1k Benign |
|---|---|---|---|---|---|
| **E0** | EWMA & Rules only (v2) | 0.0% [0.0%, 4.5%] | N/A (0% detected) | 0 of 1000 (0.299%) | 0.0 |
| **E1** | + Lineage Taint (V1) | 25.0% [16.0%, 35.9%] | 3.0 events | 0 of 1000 (0.299%) | 0.0 |
| **E2** | + Sliding Budgets (V3) | 50.0% [38.6%, 61.4%] | 4.0 events | 0 of 1000 (0.299%) | 0.0 |
| **E3** | + Canary Tripwires (V3) | 50.0% [38.6%, 61.4%] | 4.0 events | 0 of 1000 (0.299%) | 0.0 |
| **E4** | + Scanning & Pinning (V4) | 100.0% [95.5%, 100.0%] | 2.5 events | 0 of 1000 (0.299%) | 0.0 |
| **E5** | + Antibodies (V5) | 100.0% [95.5%, 100.0%] | 2.5 events | 0 of 1000 (0.299%) | 0.0 |

---

## Negative Findings and Limitations
1. **E0 Failure on Indirect Vectors**: EWMA and heuristic rules alone achieve **0.0%** detection on multi-agent confused deputy, low-and-slow exfiltration, and tool schema mutations.
2. **Single-Layer Limits**: Lineage tracking alone (E1) cannot detect low-and-slow exfiltration by authorized principals unless paired with sliding-window budget tracking (E2).
3. **Zero False-Block Trade-off**: In E5, requiring 0 observed false blocks in backtesting means candidates targeting ambiguous dual-use tools are rejected as `NOT_ENFORCEABLE`, prioritizing business continuity over raw threat block volume.

---

## Reproducibility Verification
- **Random Seed**: `42`
- **Total Trials**: `1080`
- **Identical Output Guarantee**: Running `bench/v3/run_ablations.py --seed 42` twice produces bit-for-bit identical results.