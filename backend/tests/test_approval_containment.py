"""Unit tests for the approval-status gap: ensuring approval requests record actual containment outcomes."""
import asyncio
import time
import pytest
from types import SimpleNamespace
from fastapi.testclient import TestClient

from backend.app.api import security
from backend.app.runtime.models import (
    AgentEvent,
    ApprovalRequest,
    ApprovalStatus,
    Confidence,
    DetectionResult,
    EventType,
    IncidentRecord,
    IncidentState,
    PolicyDecision,
    ThreatType,
)
from backend.app.runtime.registry import AgentRegistry
from backend.main import app

OP_KEY = "op-test-key-12345"
CS_SECRET = "cs-test-secret-67890"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(operator_api_key=OP_KEY, containment_secret=CS_SECRET),
    )


def test_registry_records_containment_outcome(tmp_path):
    async def run():
        db_path = str(tmp_path / "test_approvals.db")
        registry = AgentRegistry(db_path)
        await registry.init_db()

        req = ApprovalRequest(
            request_id="req-123",
            incident_id="inc-456",
            agent_id="customer_bot",
            threat_type=ThreatType.PROMPT_INJECTION,
            threat_score=0.92,
            proposed_action="QUARANTINE",
            status=ApprovalStatus.PENDING,
            requested_at=time.time(),
        )
        await registry.create_approval_request(req)

        pending = await registry.get_pending_approvals()
        assert len(pending) == 1
        assert pending[0].request_id == "req-123"
        assert pending[0].containment_outcome is None

        # Resolve with verified containment outcome
        await registry.resolve_approval_request(
            "req-123",
            ApprovalStatus.APPROVED,
            resolved_by=999,
            containment_outcome="QUARANTINE",
        )

        all_approvals = await registry.get_all_approvals()
        assert len(all_approvals) == 1
        assert all_approvals[0].status == ApprovalStatus.APPROVED
        assert all_approvals[0].containment_outcome == "QUARANTINE"
        assert all_approvals[0].resolved_by == 999

        # Now verify resolve with denial records "LOG (DENIED)"
        req2 = ApprovalRequest(
            request_id="req-789",
            incident_id="inc-999",
            agent_id="customer_bot",
            threat_type=ThreatType.CAPABILITY_VIOLATION,
            threat_score=0.88,
            proposed_action="QUARANTINE",
            status=ApprovalStatus.PENDING,
            requested_at=time.time(),
        )
        await registry.create_approval_request(req2)
        await registry.resolve_approval_request(
            "req-789",
            ApprovalStatus.DENIED,
            resolved_by=999,
            containment_outcome="LOG (DENIED)",
        )

        all_approvals = await registry.get_all_approvals()
        assert len(all_approvals) == 2
        denied = next(a for a in all_approvals if a.request_id == "req-789")
        assert denied.status == ApprovalStatus.DENIED
        assert denied.containment_outcome == "LOG (DENIED)"

        await registry.db.close()

    asyncio.run(run())


def test_resolve_approval_endpoint_updates_containment_outcome(client, keys, tmp_path):
    async def setup():
        db_path = str(tmp_path / "test_endpoint_approvals.db")
        registry = AgentRegistry(db_path)
        await registry.init_db()

        app.state.registry = registry
        app.state.event_bus = asyncio.Queue()

        detection = DetectionResult(
            score=0.95,
            threat_type=ThreatType.DATA_EXFILTRATION,
            confidence=Confidence.CRITICAL,
            rule_score=0.9,
            ewma_score=0.8,
            iforest_score=0.7,
            details={},
        )
        event = AgentEvent(
            agent_id="customer_bot",
            event_type=EventType.TOOL_CALL,
            target="data_export",
            payload="select * from secrets",
            payload_size=24,
        )
        inc = IncidentRecord(
            incident_id="inc-001",
            agent_id="customer_bot",
            threat_type=ThreatType.DATA_EXFILTRATION,
            detection_result=detection,
            policy_decision=PolicyDecision.ESCALATE,
            action_taken="PENDING_APPROVAL",
            explanation="High severity data exfiltration",
            event=event,
            state=IncidentState.PENDING_APPROVAL,
        )
        await registry.log_incident(inc)

        req = ApprovalRequest(
            request_id="req-001",
            incident_id="inc-001",
            agent_id="customer_bot",
            threat_type=ThreatType.DATA_EXFILTRATION,
            threat_score=0.95,
            proposed_action="QUARANTINE",
            status=ApprovalStatus.PENDING,
            requested_at=time.time(),
        )
        await registry.create_approval_request(req)
        return registry

    registry = asyncio.run(setup())

    # Fake executor that returns "QUARANTINE" on execution
    class FakeExecutor:
        async def execute_human_approved(self, incident, action, approver="dashboard"):
            return "QUARANTINE"

        async def _execute_log(self, incident):
            return None

    app.state.executor = FakeExecutor()

    # Call POST /approvals/{request_id}/resolve with approve
    res = client.post(
        "/approvals/req-001/resolve",
        json={"action": "approve"},
        headers={"X-VIGIL-Operator-Key": OP_KEY},
    )
    assert res.status_code == 200

    # Verify endpoint GET /approvals/all returns containment_outcome
    all_res = client.get("/approvals/all")
    assert all_res.status_code == 200
    approvals_data = all_res.json()
    assert len(approvals_data) == 1
    assert approvals_data[0]["request_id"] == "req-001"
    assert approvals_data[0]["status"] == "APPROVED"
    assert approvals_data[0]["containment_outcome"] == "QUARANTINE"

    # Verify legacy /telegram/approvals returns 410 Gone
    legacy_res = client.get("/telegram/approvals")
    assert legacy_res.status_code == 410
    assert "deprecated" in legacy_res.json()["detail"].lower()

    legacy_post = client.post(
        "/telegram/approvals/req-001/resolve",
        json={"action": "approve"},
        headers={"X-VIGIL-Operator-Key": OP_KEY},
    )
    assert legacy_post.status_code == 410

    asyncio.run(registry.db.close())
