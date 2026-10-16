"""Acceptance Tests for Phase M4: Proposal Workflow and UI Backend Routes."""

from __future__ import annotations

import json
import time
from uuid import uuid4
import pytest
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.app.config import settings
from backend.app.runtime.registry import AgentRegistry
from backend.app.runtime.ledger import AuditLedger
from backend.app.immune.records import ActionRecord
from backend.app.immune.workflow import (
    PolicyProposalRecord,
    ProposalConfig,
    STATUS_PROPOSED,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_EXPIRED,
    TIER_HIGH,
    TIER_LOW,
)

OPERATOR_KEY = "test-operator-key-m4"


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Sets up operator key and isolated SQLite registry and ledger."""
    monkeypatch.setattr(settings, "operator_api_key", OPERATOR_KEY)
    ledger_path = str(tmp_path / "test_ledger.jsonl")
    monkeypatch.setattr(settings, "audit_ledger_path", ledger_path)

    # Initialize isolated SQLite database
    db_path = str(tmp_path / "test_proposals.db")
    registry = AgentRegistry(db_path)
    
    import asyncio
    asyncio.run(registry.init_db())
    app.state.registry = registry

    # Wire ledger into app state
    ledger = AuditLedger(ledger_path)
    if hasattr(app.state, "gate") and app.state.gate:
        app.state.gate.ledger = ledger


@pytest.mark.anyio
async def test_missing_operator_key_returns_401_or_503(monkeypatch):
    """Acceptance test: Missing or invalid operator key returns 401 or 503."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Missing header -> 401
        res1 = await client.post("/policies/proposals", json={"agent_id": "bot_a", "tool": "exec"})
        assert res1.status_code == 401

        # 2. Invalid header -> 401
        res2 = await client.post(
            "/policies/proposals",
            headers={"X-VIGIL-Operator-Key": "wrong-key"},
            json={"agent_id": "bot_a", "tool": "exec"},
        )
        assert res2.status_code == 401

        # 3. Key unconfigured -> 503
        monkeypatch.setattr(settings, "operator_api_key", "")
        res3 = await client.post(
            "/policies/proposals",
            headers={"X-VIGIL-Operator-Key": "any-key"},
            json={"agent_id": "bot_a", "tool": "exec"},
        )
        assert res3.status_code == 503


@pytest.mark.anyio
async def test_create_proposal_only_accept_results_become_proposals():
    """Acceptance test: Only ACCEPT results become proposals. REJECT / INSUFFICIENT results fail with 422."""
    registry: AgentRegistry = app.state.registry

    # Populate 5 attacks and 700 benign calls for bot_accept -> dangerous_tool (ACCEPT)
    for i in range(5):
        await registry.log_action_record(
            ActionRecord(
                agent_id="bot_accept",
                tool="dangerous_tool",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="ATTACK",
                ts=100.0 + i,
            )
        )
    for i in range(700):
        await registry.log_action_record(
            ActionRecord(
                agent_id="bot_accept",
                tool="safe_tool",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="BENIGN_ASSUMED",
                ts=200.0 + i,
            )
        )

    # Populate insufficient traffic for bot_insufficient (1 attack, 50 benign)
    await registry.log_action_record(
        ActionRecord(
            agent_id="bot_insufficient",
            tool="rare_tool",
            mcp_id="vigil-tools",
            event_type="TOOL_CALL",
            arg_shape={"type": "dict"},
            label="ATTACK",
            ts=300.0,
        )
    )
    for i in range(50):
        await registry.log_action_record(
            ActionRecord(
                agent_id="bot_insufficient",
                tool="clean_tool",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="BENIGN_ASSUMED",
                ts=400.0 + i,
            )
        )

    headers = {"X-VIGIL-Operator-Key": OPERATOR_KEY}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. ACCEPT Candidate: creates proposal (201)
        res_accept = await client.post(
            "/policies/proposals",
            headers=headers,
            json={"agent_id": "bot_accept", "tool": "dangerous_tool", "mcp_id": "vigil-tools"},
        )
        assert res_accept.status_code == 201, f"Failed: {res_accept.status_code} -> {res_accept.text}"
        data = res_accept.json()
        assert data["agent_id"] == "bot_accept"
        assert data["tool"] == "dangerous_tool"
        assert data["status"] == "PROPOSED"
        assert data["impact_tier"] == "LOW"
        assert "yaml_diff" in data

        # 2. INSUFFICIENT Candidate: fails with 422
        res_ins = await client.post(
            "/policies/proposals",
            headers=headers,
            json={"agent_id": "bot_insufficient", "tool": "rare_tool", "mcp_id": "vigil-tools"},
        )
        assert res_ins.status_code == 422
        detail = res_ins.json()["detail"]
        assert "only ACCEPT results become proposals" in detail["message"]
        assert detail["status"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.anyio
async def test_expiry_returns_409_and_transitions_status():
    """Acceptance test: expires_at = created_at + 72 hours. Expired proposal returns 409 and becomes EXPIRED."""
    registry: AgentRegistry = app.state.registry
    now = time.time()
    past_created = now - (73 * 3600.0)  # 73 hours ago
    past_expires = past_created + (72 * 3600.0)  # expired 1 hour ago

    proposal = PolicyProposalRecord(
        id="prop-expired-001",
        status=STATUS_PROPOSED,
        agent_id="agent_alpha",
        tool="tool_x",
        impact_tier=TIER_LOW,
        replay_json=json.dumps({"status": "ACCEPT", "coverage": 1.0, "false_block_upper": 0.004}),
        assumptions_json=json.dumps({"exchangeability": "baseline"}),
        approvals_json="[]",
        created_at=past_created,
        expires_at=past_expires,
    )
    await registry.create_policy_proposal(proposal)

    headers = {"X-VIGIL-Operator-Key": OPERATOR_KEY, "X-VIGIL-Approver": "operator_alice"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Attempt to approve expired proposal -> 409 Conflict
        res = await client.post(f"/policies/proposals/{proposal.id}/approve", headers=headers)
        assert res.status_code == 409
        assert "expired" in res.json()["detail"].lower()

        # Check DB status is updated to EXPIRED
        row = await registry.get_policy_proposal(proposal.id)
        assert row["status"] == STATUS_EXPIRED

        # Get request also reflects EXPIRED
        res_get = await client.get(f"/policies/proposals/{proposal.id}")
        assert res_get.status_code == 200
        assert res_get.json()["status"] == STATUS_EXPIRED


@pytest.mark.anyio
async def test_two_approver_enforcement_for_high_impact():
    """Acceptance test: HIGH impact tier demands two distinct approvers. First leaves PROPOSED; second transitions to APPROVED."""
    registry: AgentRegistry = app.state.registry
    now = time.time()
    proposal = PolicyProposalRecord(
        id="prop-high-001",
        status=STATUS_PROPOSED,
        agent_id="critical_agent",
        tool="core_exec",
        impact_tier=TIER_HIGH,
        replay_json=json.dumps({"status": "ACCEPT", "coverage": 1.0, "false_block_upper": 0.003}),
        assumptions_json=json.dumps({"exchangeability": "baseline"}),
        approvals_json="[]",
        created_at=now,
        expires_at=now + (72 * 3600.0),
    )
    await registry.create_policy_proposal(proposal)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Approver 1: Alice
        res1 = await client.post(
            f"/policies/proposals/{proposal.id}/approve",
            headers={"X-VIGIL-Operator-Key": OPERATOR_KEY, "X-VIGIL-Approver": "alice"},
        )
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["status"] == "PROPOSED"
        assert data1["approval_progress"] == "1 of 2"
        assert json.loads(data1["approvals_json"]) == ["alice"]

        # Approver 2: Bob (second distinct approver)
        res2 = await client.post(
            f"/policies/proposals/{proposal.id}/approve",
            headers={"X-VIGIL-Operator-Key": OPERATOR_KEY, "X-VIGIL-Approver": "bob"},
        )
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["status"] == "APPROVED"
        assert data2["approval_progress"] == "2 of 2"
        assert json.loads(data2["approvals_json"]) == ["alice", "bob"]
        assert data2["decided_at"] is not None


@pytest.mark.anyio
async def test_duplicate_approver_is_ignored():
    """Acceptance test: A repeat approval from the same approver changes nothing."""
    registry: AgentRegistry = app.state.registry
    now = time.time()
    proposal = PolicyProposalRecord(
        id="prop-dup-001",
        status=STATUS_PROPOSED,
        agent_id="critical_agent",
        tool="core_exec",
        impact_tier=TIER_HIGH,
        replay_json=json.dumps({"status": "ACCEPT", "coverage": 1.0, "false_block_upper": 0.003}),
        assumptions_json=json.dumps({"exchangeability": "baseline"}),
        approvals_json="[]",
        created_at=now,
        expires_at=now + (72 * 3600.0),
    )
    await registry.create_policy_proposal(proposal)

    headers = {"X-VIGIL-Operator-Key": OPERATOR_KEY, "X-VIGIL-Approver": "alice"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First call: Alice
        res1 = await client.post(f"/policies/proposals/{proposal.id}/approve", headers=headers)
        assert res1.status_code == 200
        assert res1.json()["approval_progress"] == "1 of 2"

        # Second call: Alice again
        res2 = await client.post(f"/policies/proposals/{proposal.id}/approve", headers=headers)
        assert res2.status_code == 200
        data2 = res2.json()
        # Status remains PROPOSED, progress is still 1 of 2
        assert data2["status"] == "PROPOSED"
        assert data2["approval_progress"] == "1 of 2"
        assert json.loads(data2["approvals_json"]) == ["alice"]


@pytest.mark.anyio
async def test_rejection_workflow():
    """Acceptance test: Rejecting a proposal transitions status to REJECTED."""
    registry: AgentRegistry = app.state.registry
    now = time.time()
    proposal = PolicyProposalRecord(
        id="prop-reject-001",
        status=STATUS_PROPOSED,
        agent_id="agent_beta",
        tool="tool_y",
        impact_tier=TIER_LOW,
        replay_json=json.dumps({"status": "ACCEPT"}),
        assumptions_json=json.dumps({}),
        approvals_json="[]",
        created_at=now,
        expires_at=now + (72 * 3600.0),
    )
    await registry.create_policy_proposal(proposal)

    headers = {"X-VIGIL-Operator-Key": OPERATOR_KEY, "X-VIGIL-Approver": "charlie"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(f"/policies/proposals/{proposal.id}/reject", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "REJECTED"
        assert data["decided_at"] is not None


@pytest.mark.anyio
async def test_ledger_entries_recorded_with_approver_identity():
    """Acceptance test: Every state change writes a ledger entry that records the approver identity."""
    registry: AgentRegistry = app.state.registry
    now = time.time()
    proposal = PolicyProposalRecord(
        id="prop-ledger-001",
        status=STATUS_PROPOSED,
        agent_id="audit_agent",
        tool="delete_logs",
        impact_tier=TIER_LOW,
        replay_json=json.dumps({"status": "ACCEPT"}),
        assumptions_json=json.dumps({}),
        approvals_json="[]",
        created_at=now,
        expires_at=now + (72 * 3600.0),
    )
    await registry.create_policy_proposal(proposal)

    # Approve with specific approver
    headers = {"X-VIGIL-Operator-Key": OPERATOR_KEY, "X-VIGIL-Approver": "diana_admin"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(f"/policies/proposals/{proposal.id}/approve", headers=headers)
        assert res.status_code == 200

    # Verify ledger entries
    ledger = AuditLedger(settings.audit_ledger_path)
    verify_res = ledger.verify()
    assert verify_res.ok
    assert verify_res.entries >= 1

    # Read records and assert approver identity is present
    found = False
    with open(settings.audit_ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            rec = entry.get("record", {})
            if rec.get("proposal_id") == "prop-ledger-001":
                assert rec.get("approver") == "diana_admin"
                assert rec.get("status") == "APPROVED"
                found = True
    assert found, "Ledger entry with approver identity not found in ledger file!"
