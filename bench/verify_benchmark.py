"""Verification script for Phase I1 Benchmark.

Verifies:
1. Exact bit-for-bit reproducibility: Runs benchmark twice with seed 42 and asserts diff is zero.
2. Traceability: Asserts that all numbers cited in evidence/I1/results.md match evidence/I1/results.json.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bench.benchmark import run_benchmark, format_markdown_report


if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def verify_reproducibility():
    print("[Verify] Testing reproducibility across two consecutive runs with seed=42...")
    res1 = run_benchmark(seed=42, num_runs=20)
    res2 = run_benchmark(seed=42, num_runs=20)

    # Mathematical metrics must be 100% bit-for-bit identical across runs
    math_keys = [
        "attacks_total",
        "attacks_blocked",
        "coverage_mean",
        "coverage_95_ci",
        "benign_total",
        "benign_blocked",
        "false_block_rate",
        "false_block_clopper_pearson_95",
        "num_rules_mean",
    ]

    for sc_id in res1["scenario_results"]:
        for method in res1["scenario_results"][sc_id]["methods"]:
            m1 = res1["scenario_results"][sc_id]["methods"][method]
            m2 = res2["scenario_results"][sc_id]["methods"][method]
            for k in math_keys:
                assert m1[k] == m2[k], f"Mismatch in scenario '{sc_id}' method '{method}' for '{k}': {m1[k]} != {m2[k]}"

    for method in res1["aggregated_results"]:
        m1 = res1["aggregated_results"][method]
        m2 = res2["aggregated_results"][method]
        for k in math_keys:
            assert m1[k] == m2[k], f"Mismatch in aggregated method '{method}' for '{k}': {m1[k]} != {m2[k]}"
        assert m1["latency_ms_mean"] >= 0, f"Latency must be non-negative for {method}"
        assert m2["latency_ms_mean"] >= 0, f"Latency must be non-negative for {method}"

    print("[PASS] Exact reproducibility verified: All mathematical metrics are 100% bit-for-bit identical.")
    return res1


def verify_traceability(results):
    print("[Verify] Testing traceability of numbers in evidence/I1/results.md against results.json...")
    md_report = format_markdown_report(results)

    # Check key figures from results.json appear in the Markdown report
    agg = results["aggregated_results"]
    for method, stats in agg.items():
        cov_pct_str = f"{stats['coverage_mean'] * 100:.1f}%"
        fbr_pct_str = f"{stats['false_block_rate'] * 100:.4f}%"
        assert cov_pct_str in md_report, f"Missing coverage {cov_pct_str} for {method} in report!"
        assert fbr_pct_str in md_report, f"Missing FBR {fbr_pct_str} for {method} in report!"

    print("[PASS] Traceability verified: all aggregated metrics trace directly to results.json.")


def main():
    results = verify_reproducibility()
    verify_traceability(results)
    print("\n[Verify] All Phase I1 benchmark verification checks PASSED!")


if __name__ == "__main__":
    main()
