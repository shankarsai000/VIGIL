"""Test suite for Feature B: Explainable Denials.

Verifies:
1. Denials matched with an approved policy proposal return full provenance:
   rule ID, proposal ID, coverage, false-block bound, replay window, trace ID,
   with source="policy_immune" and policy_driven=True.
2. A planted denial with no matching proposal returns source="unknown" and policy_driven=False.
3. Denials never invent explanations; all values originate strictly from stored records.
4. Non-existent trace_ids or non-DENY actions return source="unknown".
"""

from __future__ import annotations

import asyncio
import json
import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.app.runtime.registry import AgentRegistry
from backend.app.immune.records import ActionRecord
from backend.app.immune.workflow import (
    PolicyProposalRecord,
    STATUS_APPROVED,
    STATUS_PROPOSED,
    STATUS_REJECTED,
    TIER_LOW,
)
from backend.app.config import settings


@pytest.fixture
def client():
    return TestClient(app)


def test_planted_denial_no_proposal_returns_source_unknown(client):
    """A planted denial with no matching proposal must return source: unknown."""
    async def _setup():
        registry = AgentRegistry("sqlite:///:memory:")
        await registry.init_db()
        app.state.registry = registry

        # Plant an action record with decision DENY
        trace_id = f"trace-{uuid4().hex[:12]}"
        action = ActionRecord(
            record_id=f"rec-{uuid4().hex[:8]}",
            trace_id=trace_id,
            agent_id="test-agent",
            tool="unregistered_tool",
            event_type="TOOL_CALL",
            arg_shape={"type": "dict"},
            observed_decision="DENY",
            ts=time.time(),
        )
        await registry.log_action_records_batch([action])
        return trace_id

    trace_id = asyncio.run(_setup())

    resp = client.get(f"/denials/{trace_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["trace_id"] == trace_id
    assert data["source"] == "unknown"
    assert data["policy_driven"] is False
    assert "No matching approved policy proposal" in data.get("message", "")


def test_denial_with_approved_proposal_returns_provenance(client):
    """A denial matching an approved proposal must return full rule, proposal, and replay metrics."""
    prop_id = f"prop-{uuid4().hex[:8]}"
    trace_id = f"trace-{uuid4().hex[:12]}"

    async def _setup():
        registry = AgentRegistry("sqlite:///:memory:")
        await registry.init_db()
        app.state.registry = registry

        # 1. Create an approved policy proposal with replay metrics
        replay_metrics = {
            "coverage": 0.942,
            "false_block_upper": 0.0085,
            "benign_total": 450,
            "attacks_total": 52,
            "attacks_blocked": 49,
        }
        proposal = PolicyProposalRecord(
            id=prop_id,
            status=STATUS_APPROVED,
            agent_id="customer-bot",
            mcp_id="vigil-tools",
            tool="billing_database",
            impact_tier=TIER_LOW,
            replay_json=json.dumps(replay_metrics),
            assumptions_json=json.dumps({"benign_traffic_represented": True}),
            approvals_json=json.dumps(["lead@corp.internal"]),
            created_at=time.time() - 3600,
            decided_at=time.time() - 1800,
            expires_at=time.time() + 86400,
            version=1,
        )
        await registry.create_policy_proposal(proposal)

        # 2. Save a denial action record for the same agent and tool
        action = ActionRecord(
            record_id=f"rec-{uuid4().hex[:8]}",
            trace_id=trace_id,
            agent_id="customer-bot",
            mcp_id="vigil-tools",
            tool="billing_database",
            event_type="TOOL_CALL",
            arg_shape={"type": "dict", "keys": ["query"]},
            observed_decision="DENY",
            ts=time.time(),
        )
        await registry.log_action_records_batch([action])

    asyncio.run(_setup())

    resp = client.get(f"/denials/{trace_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["trace_id"] == trace_id
    assert data["source"] == "policy_immune"
    assert data["policy_driven"] is True
    assert data["proposal_id"] == prop_id
    assert data["rule_id"] == "rule-customer-bot-billing_database"
    assert data["agent_id"] == "customer-bot"
    assert data["tool"] == "billing_database"
    assert data["coverage"] == 0.942
    assert data["false_block_bound"] == 0.0085
    assert data["replay_window"]["benign_total"] == 450
    assert data["replay_window"]["attacks_total"] == 52
    assert data["replay_window"]["attacks_blocked"] == 49


def test_unapproved_proposal_does_not_label_denial_as_policy_driven(client):
    """A proposed or rejected proposal must NOT label a denial as policy-driven."""
    prop_id = f"prop-{uuid4().hex[:8]}"
    trace_id = f"trace-{uuid4().hex[:12]}"

    async def _setup():
        registry = AgentRegistry("sqlite:///:memory:")
        await registry.init_db()
        app.state.registry = registry

        # Create proposal in PROPOSED (unapproved) state
        proposal = PolicyProposalRecord(
            id=prop_id,
            status=STATUS_PROPOSED,
            agent_id="customer-bot",
            tool="billing_database",
            impact_tier=TIER_LOW,
            replay_json=json.dumps({"coverage": 1.0, "false_block_upper": 0.01}),
            assumptions_json="{}",
            approvals_json="[]",
            created_at=time.time() - 3600,
            expires_at=time.time() + 86400,
            version=1,
        )
        await registry.create_policy_proposal(proposal)

        action = ActionRecord(
            record_id=f"rec-{uuid4().hex[:8]}",
            trace_id=trace_id,
            agent_id="customer-bot",
            tool="billing_database",
            event_type="TOOL_CALL",
            arg_shape={"type": "dict"},
            observed_decision="DENY",
            ts=time.time(),
        )
        await registry.log_action_records_batch([action])

    asyncio.run(_setup())

    resp = client.get(f"/denials/{trace_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["source"] == "unknown"
    assert data["policy_driven"] is False


def test_nonexistent_trace_returns_source_unknown(client):
    """A query for a non-existent trace ID returns source: unknown."""
    resp = client.get("/denials/non-existent-trace-id-999")
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "unknown"
    assert data["policy_driven"] is False
