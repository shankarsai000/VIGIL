"""Test suite for VIGIL DIFC Provenance & Lineage Engine (Phase V1).

Verifies:
1. Monotonic taint propagation along multi-hop agent delegation chains.
2. Circular delegation detection via graph walk marking lineage DEGRADED.
3. Delegation depth bounds enforcement (> 6 hops marks DEGRADED).
4. Fail-closed behavior: missing lineage denies all restricted sinks.
5. Mint-time policy derivation: tainted lineage generates inline deny for privileged sinks.
6. Benchmark on 2,000 benign delegations reporting false-taint rate with Clopper-Pearson bound.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
from scipy.stats import beta as beta_dist

from backend.app.provenance.lineage import (
    LineageRecord,
    ProvenanceTracker,
    STATUS_DEGRADED,
    STATUS_VALID,
    TaintLevel,
    TraceLineage,
)


@pytest.fixture
def tracker(tmp_path):
    ledger = tmp_path / "test_audit_ledger.jsonl"
    return ProvenanceTracker(ledger_path=ledger)


def test_monotonic_taint_propagation(tracker):
    """Taint must monotonically increase across delegation hops and never decrease."""
    trace_id = f"trace-{uuid4().hex[:8]}"

    # Step 1: Agent A receives SYSTEM_TRUSTED prompt
    rec1 = tracker.record_input(
        trace_id=trace_id,
        to_agent="agent_a",
        input_taint=TaintLevel.SYSTEM_TRUSTED,
        source_label="system_init",
    )
    assert rec1.taint == TaintLevel.SYSTEM_TRUSTED

    # Step 2: Agent A receives USER_UNTRUSTED query
    rec2 = tracker.record_input(
        trace_id=trace_id,
        to_agent="agent_a",
        input_taint=TaintLevel.USER_UNTRUSTED,
        source_label="user_chat",
    )
    lineage = tracker.get_lineage(trace_id)
    assert lineage.current_taint == TaintLevel.USER_UNTRUSTED

    # Step 3: Agent A delegates to Agent B with VERIFIED_INTERNAL sub-task
    # Child's effective taint must remain USER_UNTRUSTED (cannot decrease)
    rec3 = tracker.propagate_delegation(
        trace_id=trace_id,
        from_agent="agent_a",
        to_agent="agent_b",
        payload_taint=TaintLevel.VERIFIED_INTERNAL,
        source_label="internal_rpc",
    )
    assert rec3.taint == TaintLevel.USER_UNTRUSTED
    lineage = tracker.get_lineage(trace_id)
    assert lineage.current_taint == TaintLevel.USER_UNTRUSTED

    # Step 4: Agent B delegates to Agent C with EXTERNAL_UNTRUSTED payload
    # Taint increases to EXTERNAL_UNTRUSTED
    rec4 = tracker.propagate_delegation(
        trace_id=trace_id,
        from_agent="agent_b",
        to_agent="agent_c",
        payload_taint=TaintLevel.EXTERNAL_UNTRUSTED,
        source_label="unverified_web_hook",
    )
    assert rec4.taint == TaintLevel.EXTERNAL_UNTRUSTED
    lineage = tracker.get_lineage(trace_id)
    assert lineage.current_taint == TaintLevel.EXTERNAL_UNTRUSTED


def test_cycle_detection_marks_degraded(tracker):
    """Circular delegation loops (A -> B -> C -> A) must mark lineage DEGRADED."""
    trace_id = f"trace-{uuid4().hex[:8]}"
    tracker.record_input(trace_id, "agent_a", TaintLevel.VERIFIED_INTERNAL, "init")

    # A -> B
    tracker.propagate_delegation(trace_id, "agent_a", "agent_b", TaintLevel.VERIFIED_INTERNAL, "hop1")
    assert tracker.get_lineage(trace_id).status == STATUS_VALID

    # B -> C
    tracker.propagate_delegation(trace_id, "agent_b", "agent_c", TaintLevel.VERIFIED_INTERNAL, "hop2")
    assert tracker.get_lineage(trace_id).status == STATUS_VALID

    # C -> A (Cycle!)
    rec_cycle = tracker.propagate_delegation(trace_id, "agent_c", "agent_a", TaintLevel.VERIFIED_INTERNAL, "hop3")
    assert rec_cycle.status == STATUS_DEGRADED
    assert "Delegation cycle detected" in rec_cycle.degraded_reason

    lineage = tracker.get_lineage(trace_id)
    assert lineage.status == STATUS_DEGRADED
    assert "Delegation cycle detected" in lineage.degraded_reason


def test_depth_overflow_marks_degraded(tracker):
    """Delegations exceeding max_delegation_depth (default: 6) must mark lineage DEGRADED."""
    trace_id = f"trace-{uuid4().hex[:8]}"
    tracker.record_input(trace_id, "agent_0", TaintLevel.VERIFIED_INTERNAL, "init")

    # Perform 7 hops: agent_0 -> agent_1 -> ... -> agent_7
    for i in range(7):
        rec = tracker.propagate_delegation(
            trace_id=trace_id,
            from_agent=f"agent_{i}",
            to_agent=f"agent_{i+1}",
            payload_taint=TaintLevel.VERIFIED_INTERNAL,
            source_label=f"hop_{i}",
        )

    lineage = tracker.get_lineage(trace_id)
    assert lineage.status == STATUS_DEGRADED
    assert "depth exceeded" in lineage.degraded_reason.lower()


def test_missing_lineage_fails_closed(tracker):
    """A missing lineage record produces an inline policy denying all restricted sinks."""
    policy = tracker.derive_mint_policy(
        trace_id="non-existent-trace-999",
        target_tool="billing_database",
    )
    assert len(policy["deny"]) > 0
    assert any("billing_database" in d for d in policy["deny"])
    assert policy["allow"] == []
    assert "Missing lineage trace record" in policy["reason"]


def test_tainted_lineage_denies_restricted_sink(tracker):
    """An external tainted lineage attempting to access billing_database produces an inline deny."""
    trace_id = f"trace-{uuid4().hex[:8]}"
    tracker.record_input(
        trace_id=trace_id,
        to_agent="customer_bot",
        input_taint=TaintLevel.EXTERNAL_UNTRUSTED,
        source_label="incoming_external_email",
    )

    # billing_database ceiling is VERIFIED_INTERNAL. EXTERNAL_UNTRUSTED > VERIFIED_INTERNAL.
    policy = tracker.derive_mint_policy(
        trace_id=trace_id,
        target_tool="billing_database",
        target_mcp="vigil-tools",
    )
    assert policy["deny"] == ["vigil-tools/billing_database"]
    assert policy["allow"] == []
    assert "DIFC taint violation" in policy["reason"]


def test_benign_verified_lineage_allows_restricted_sink(tracker):
    """A clean internal lineage within permissible ceiling produces an allow policy."""
    trace_id = f"trace-{uuid4().hex[:8]}"
    tracker.record_input(
        trace_id=trace_id,
        to_agent="finance_agent",
        input_taint=TaintLevel.VERIFIED_INTERNAL,
        source_label="authenticated_erp_session",
    )

    policy = tracker.derive_mint_policy(
        trace_id=trace_id,
        target_tool="billing_database",
        target_mcp="vigil-tools",
    )
    assert policy["deny"] == []
    assert policy["allow"] == ["vigil-tools/billing_database"]
    assert "Lineage verified" in policy["reason"]


def test_benign_delegation_benchmark_bounds(tracker):
    """Benchmarks false-taint rate on 2,000 benign delegations and computes 95% Clopper-Pearson bound."""
    import random
    rng = random.Random(42)

    num_delegations = 2000
    false_taint_count = 0

    agents = ["customer_bot", "support_agent", "hr_agent", "devops_bot", "sales_agent"]

    for i in range(num_delegations):
        t_id = f"trace-bench-{i:05d}"
        # Benign internal flows start with VERIFIED_INTERNAL or SYSTEM_TRUSTED
        init_taint = rng.choice([TaintLevel.SYSTEM_TRUSTED, TaintLevel.VERIFIED_INTERNAL])
        tracker.record_input(t_id, agents[0], init_taint, "benign_flow")

        hops = rng.randint(1, 4)
        for h in range(hops):
            a_from = agents[h % len(agents)]
            a_to = agents[(h + 1) % len(agents)]
            # In benign summarization, internal delegation carries verified state
            step_taint = rng.choice([TaintLevel.SYSTEM_TRUSTED, TaintLevel.VERIFIED_INTERNAL])
            rec = tracker.propagate_delegation(t_id, a_from, a_to, step_taint, f"hop_{h}")

            # Check if any benign delegation erroneously escalated to USER_UNTRUSTED or EXTERNAL_UNTRUSTED
            if rec.taint >= TaintLevel.USER_UNTRUSTED:
                false_taint_count += 1

    # Exact Clopper-Pearson 95% one-sided bound
    alpha = 0.05
    if false_taint_count == 0:
        cp_upper = 1.0 - (alpha ** (1.0 / num_delegations))
    else:
        cp_upper = float(beta_dist.ppf(1.0 - alpha, false_taint_count + 1, num_delegations - false_taint_count))

    assert false_taint_count == 0
    # For n=2000, 1 - 0.05^(1/2000) ≈ 0.00149 (0.149%)
    assert cp_upper <= 0.002
