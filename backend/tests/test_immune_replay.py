"""Offline Acceptance Tests for Phase M2: Replay Engine and the False-Block Bound."""

import ast
import json
import math
from typing import List
import pytest
from scipy.stats import beta as beta_dist

from backend.app.immune.records import ActionRecord, compute_arg_shape
from backend.app.immune.replay import (
    CandidateRule,
    ReplayReport,
    ReplayEngine,
    compute_false_block_upper,
    evaluate_candidate_rule,
)


def test_exact_clopper_pearson_zero_blocks():
    """Acceptance test: With zero benign blocks and benign_total = 600, false_block_upper equals 1 - 0.05 ** (1/600) within 1e-9."""
    delta = 0.05
    n = 600
    k = 0

    computed_bound = compute_false_block_upper(benign_blocked=k, benign_total=n, delta=delta)
    analytic_bound = 1.0 - (delta ** (1.0 / n))

    diff = abs(computed_bound - analytic_bound)
    print(f"\n[Formula Check] Computed={computed_bound:.16f}, Analytic={analytic_bound:.16f}, Diff={diff:.2e}")

    assert diff < 1e-9, f"Bound diff {diff} exceeds 1e-9 tolerance!"
    # With n=600 and k=0, the bound must be under the 0.005 threshold
    assert computed_bound <= 0.005, f"Expected <= 0.005, got {computed_bound}"

    # Also verify across additional sample sizes n in [100, 300, 1000, 5000]
    for sample_n in [100, 300, 1000, 5000]:
        c = compute_false_block_upper(0, sample_n, delta=delta)
        a = 1.0 - (delta ** (1.0 / sample_n))
        assert abs(c - a) < 1e-9


def test_monotonicity_fixed_total_growing_blocked():
    """Acceptance test: For fixed benign_total, the bound never decreases as benign_blocked grows."""
    n = 1000
    prev_bound = -1.0

    for k in range(0, 100):
        current_bound = compute_false_block_upper(benign_blocked=k, benign_total=n, delta=0.05)
        if prev_bound >= 0.0:
            assert current_bound >= prev_bound, (
                f"Monotonicity violation at k={k}: current {current_bound} < previous {prev_bound}"
            )
        prev_bound = current_bound


def test_monotonicity_fixed_blocked_growing_total():
    """Acceptance test: For fixed benign_blocked, the bound never increases as benign_total grows."""
    k = 2
    prev_bound = 2.0

    for n in range(500, 2000, 50):
        current_bound = compute_false_block_upper(benign_blocked=k, benign_total=n, delta=0.05)
        if prev_bound <= 1.0:
            assert current_bound <= prev_bound, (
                f"Monotonicity violation at n={n}: current {current_bound} > previous {prev_bound}"
            )
        prev_bound = current_bound


def test_known_answer_fixtures():
    """Acceptance test: Known-answer tests on fixtures with hand-computed counts."""
    candidate = CandidateRule(agent_id="bot_alpha", tool="dangerous_tool")

    def _make_records(
        num_attacks_matching: int,
        num_attacks_other: int,
        num_benign_matching: int,
        num_benign_other: int,
    ) -> List[ActionRecord]:
        recs = []
        # Attacks matching candidate tool
        for i in range(num_attacks_matching):
            recs.append(
                ActionRecord(
                    agent_id="bot_alpha",
                    tool="dangerous_tool",
                    event_type="TOOL_CALL",
                    arg_shape={"type": "dict"},
                    label="ATTACK",
                    label_source="simulator_ground_truth",
                    ts=100.0 + i,
                )
            )
        # Attacks on other tools
        for i in range(num_attacks_other):
            recs.append(
                ActionRecord(
                    agent_id="bot_alpha",
                    tool="harmless_tool",
                    event_type="TOOL_CALL",
                    arg_shape={"type": "dict"},
                    label="ATTACK",
                    label_source="simulator_ground_truth",
                    ts=200.0 + i,
                )
            )
        # Benign matching candidate tool (false blocks)
        for i in range(num_benign_matching):
            recs.append(
                ActionRecord(
                    agent_id="bot_alpha",
                    tool="dangerous_tool",
                    event_type="TOOL_CALL",
                    arg_shape={"type": "dict"},
                    label="BENIGN_ASSUMED",
                    label_source="simulator_ground_truth",
                    ts=300.0 + i,
                )
            )
        # Benign on other tools (clean legitimate calls)
        for i in range(num_benign_other):
            recs.append(
                ActionRecord(
                    agent_id="bot_alpha",
                    tool="harmless_tool",
                    event_type="TOOL_CALL",
                    arg_shape={"type": "dict"},
                    label="BENIGN_ASSUMED",
                    label_source="simulator_ground_truth",
                    ts=400.0 + i,
                )
            )
        return recs

    # Case 1: ACCEPT
    # 10 matching attacks (coverage=1.0), 0 benign blocks, 650 benign total (>=600)
    # false_block_upper = 1 - 0.05**(1/650) = 0.00459 <= 0.005
    recs_accept = _make_records(10, 0, 0, 650)
    rep_accept = evaluate_candidate_rule(recs_accept, candidate)
    assert rep_accept.status == "ACCEPT"
    assert rep_accept.attacks_total == 10
    assert rep_accept.attacks_blocked == 10
    assert rep_accept.coverage == 1.0
    assert rep_accept.benign_total == 650
    assert rep_accept.benign_blocked == 0
    assert rep_accept.false_block_point == 0.0
    assert rep_accept.false_block_upper <= 0.005

    # Case 2: REJECT due to false blocks
    # 10 matching attacks (coverage=1.0), 5 benign blocks out of 650 total
    recs_rej_fb = _make_records(10, 0, 5, 645)
    rep_rej_fb = evaluate_candidate_rule(recs_rej_fb, candidate)
    assert rep_rej_fb.status == "REJECT"
    assert rep_rej_fb.coverage == 1.0
    assert rep_rej_fb.benign_blocked == 5
    assert rep_rej_fb.false_block_upper > 0.005

    # Case 3: REJECT due to low coverage
    # 5 matching attacks out of 10 total (coverage=0.5 < 0.90), 0 benign blocks out of 650 total
    recs_rej_cov = _make_records(5, 5, 0, 650)
    rep_rej_cov = evaluate_candidate_rule(recs_rej_cov, candidate)
    assert rep_rej_cov.status == "REJECT"
    assert rep_rej_cov.attacks_total == 10
    assert rep_rej_cov.attacks_blocked == 5
    assert rep_rej_cov.coverage == 0.5

    # Case 4: INSUFFICIENT_EVIDENCE due to benign sample size < 600
    # 10 matching attacks, 0 benign blocks out of 300 total
    recs_ins_benign = _make_records(10, 0, 0, 300)
    rep_ins_benign = evaluate_candidate_rule(recs_ins_benign, candidate)
    assert rep_ins_benign.status == "INSUFFICIENT_EVIDENCE"
    assert rep_ins_benign.benign_total == 300 < 600

    # Case 5: INSUFFICIENT_EVIDENCE due to attack sample size < 3
    # 2 matching attacks (< 3), 0 benign blocks out of 700 total
    recs_ins_attack = _make_records(2, 0, 0, 700)
    rep_ins_attack = evaluate_candidate_rule(recs_ins_attack, candidate)
    assert rep_ins_attack.status == "INSUFFICIENT_EVIDENCE"
    assert rep_ins_attack.attacks_total == 2 < 3


def test_replay_module_has_no_network_or_database_imports():
    """Acceptance test: Enforces that the replay module imports no network or database code."""
    import inspect
    from backend.app.immune import replay

    source_path = inspect.getfile(replay)
    with open(source_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=source_path)

    # Disallowed network & database module prefixes
    forbidden_modules = {
        "httpx", "requests", "urllib", "socket", "http", "aiohttp", "websockets",
        "asyncpg", "aiosqlite", "sqlite3", "psycopg2", "psycopg", "sqlalchemy",
        "redis", "pymongo", "database", "registry",
    }

    imported_names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.append(node.module)

    for name in imported_names:
        base_pkg = name.split(".")[0]
        assert base_pkg not in forbidden_modules, (
            f"Pure replay module violates isolation by importing forbidden library: {name}"
        )

    print(f"\n[Isolation Check] Replay module imports: {imported_names} (all pure).")


def test_replay_report_json_and_assumptions():
    """Verifies that ReplayReport includes the required assumptions block and serializes cleanly to JSON."""
    candidate = CandidateRule(agent_id="customer_bot", tool="system_override")
    recs = [
        ActionRecord(
            agent_id="customer_bot",
            tool="system_override",
            event_type="TOOL_CALL",
            arg_shape={"type": "dict"},
            label="ATTACK",
            ts=100.0,
        )
    ]
    report = evaluate_candidate_rule(recs, candidate)
    report_json_str = report.to_json()
    parsed = json.loads(report_json_str)

    assert "assumptions" in parsed
    assumptions = parsed["assumptions"]
    assert "exchangeability" in assumptions
    assert "assumed_benign_labels" in assumptions
    assert "window_bounds" in assumptions
    assert assumptions["window_bounds"]["records_evaluated"] == 1
    assert parsed["candidate_rule"]["tool"] == "system_override"
