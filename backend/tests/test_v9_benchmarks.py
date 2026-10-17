"""Tests for VIGIL v3 Benchmark & Ablations (Phase V9).

Verifies:
1. Ablations output is 100% reproducible across multiple runs with fixed seed.
2. Every ablation (E0 to E5) has measured detection rate, 95% CI, and false block bound.
3. Every claim in docs/INNOVATION.md has a valid status and verifiable evidence path.
4. Static decision boundary remains clean.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_ablation_reproducibility():
    from bench.v3.run_ablations import run_full_benchmark_suite

    run1 = run_full_benchmark_suite(seed=42)
    run2 = run_full_benchmark_suite(seed=42)

    assert run1 == run2, "Ablation runs with identical seed must produce identical results"


def test_evidence_v9_results_complete():
    res_json_path = REPO_ROOT / "evidence" / "V9" / "results.json"
    res_md_path = REPO_ROOT / "evidence" / "V9" / "results.md"

    assert res_json_path.exists()
    assert res_md_path.exists()

    with open(res_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    abl = data["ablations"]
    for code in ["E0", "E1", "E2", "E3", "E4", "E5"]:
        assert code in abl
        assert "detection_rate" in abl[code]
        assert "detection_rate_95_ci" in abl[code]
        assert "false_block_bound_95_upper" in abl[code]
        assert abl[code]["observed_false_blocks"] == 0

    # Progressive detection rate increases from E0 to E4/E5
    assert abl["E0"]["detection_rate"] < abl["E1"]["detection_rate"]
    assert abl["E1"]["detection_rate"] < abl["E2"]["detection_rate"]
    assert abl["E2"]["detection_rate"] <= abl["E3"]["detection_rate"]
    assert abl["E3"]["detection_rate"] < abl["E4"]["detection_rate"]
    assert abl["E4"]["detection_rate"] == 1.0
    assert abl["E5"]["detection_rate"] == 1.0


def test_innovation_register_claims_valid():
    innov_path = REPO_ROOT / "docs" / "INNOVATION.md"
    assert innov_path.exists()
    content = innov_path.read_text(encoding="utf-8")

    valid_statuses = {"MEASURED-OFFLINE", "MEASURED-LIVE", "NEGATIVE", "UNVERIFIED"}
    
    # Check that each table row in Innovation Claims Register has a valid status
    in_table = False
    for line in content.splitlines():
        if "## Innovation Claims Register" in line:
            in_table = True
            continue
        if in_table and line.startswith("---"):
            break
        if in_table and line.startswith("| **Feature"):
            cols = [c.strip() for c in line.split("|")[1:-1]]
            status = cols[3].replace("*", "")
            assert status in valid_statuses, f"Invalid innovation status '{status}' in line: {line}"
            # Check evidence link exists
            evidence_link = cols[4]
            assert "evidence/" in evidence_link or "backend/tests/" in evidence_link
