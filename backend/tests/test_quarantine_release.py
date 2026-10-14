"""Tests for P0-1: Quarantine release only by human operator and simulator immunity."""
import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from backend.app.api import security
from backend.app.runtime.models import AgentProfile, AgentStatus
from backend.app.runtime.ledger import AuditLedger
from backend.app.runtime.simulator import DynamicTrafficSimulator
from backend.main import app

OP_KEY = "test-operator-key-xyz"
CS_SECRET = "test-containment-secret"


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


class MockAgentProfile:
    def __init__(self, agent_id: str, status: AgentStatus):
        self.agent_id = agent_id
        self.status = status

    def model_dump(self, mode="json"):
        return {"agent_id": self.agent_id, "status": self.status.value}


class FakeRegistryForRelease:
    def __init__(self):
        self.agents = {
            "agent-quarantined": MockAgentProfile("agent-quarantined", AgentStatus.QUARANTINED),
            "agent-normal": MockAgentProfile("agent-normal", AgentStatus.NORMAL),
        }
        self.sources = {"agent-quarantined": "gate"}

    async def get_agent(self, agent_id: str):
        return self.agents.get(agent_id)

    async def list_agents(self):
        return list(self.agents.values())

    async def update_status(self, agent_id: str, status: AgentStatus, source: str = None):
        if agent_id in self.agents:
            self.agents[agent_id].status = status
        if status == AgentStatus.QUARANTINED:
            self.sources[agent_id] = source or "gate"
        else:
            self.sources.pop(agent_id, None)

    def get_quarantine_source(self, agent_id: str):
        return self.sources.get(agent_id)


def test_release_route_requires_operator_key(client, keys):
    # Missing key
    resp = client.post("/agents/agent-quarantined/release", json={"reason": "Human reviewed"})
    assert resp.status_code == 401

    # Wrong key
    resp = client.post(
        "/agents/agent-quarantined/release",
        headers={"X-VIGIL-Operator-Key": "bad-key"},
        json={"reason": "Human reviewed"},
    )
    assert resp.status_code == 401


def test_release_route_requires_reason(client, keys):
    fake_reg = FakeRegistryForRelease()
    app.state.registry = fake_reg
    app.state.event_bus = AsyncMock()

    resp = client.post(
        "/agents/agent-quarantined/release",
        headers={"X-VIGIL-Operator-Key": OP_KEY},
        json={"reason": "   "},
    )
    assert resp.status_code == 400
    assert "reason is required" in resp.json()["detail"]


def test_release_route_rejects_unquarantined_or_unknown_agent(client, keys):
    fake_reg = FakeRegistryForRelease()
    app.state.registry = fake_reg
    app.state.event_bus = AsyncMock()

    # Unknown agent
    resp = client.post(
        "/agents/nonexistent-agent/release",
        headers={"X-VIGIL-Operator-Key": OP_KEY},
        json={"reason": "Human reviewed"},
    )
    assert resp.status_code == 404

    # Agent is not quarantined
    resp = client.post(
        "/agents/agent-normal/release",
        headers={"X-VIGIL-Operator-Key": OP_KEY},
        json={"reason": "Human reviewed"},
    )
    assert resp.status_code == 400
    assert "not currently quarantined" in resp.json()["detail"]


def test_release_route_success_updates_status_and_ledger(client, keys, tmp_path):
    fake_reg = FakeRegistryForRelease()
    app.state.registry = fake_reg
    app.state.event_bus = AsyncMock()

    ledger = AuditLedger(str(tmp_path / "test_ledger.jsonl"))
    gate = SimpleNamespace(ledger=ledger, mode="live")
    app.state.gate = gate

    resp = client.post(
        "/agents/agent-quarantined/release",
        headers={"X-VIGIL-Operator-Key": OP_KEY},
        json={"reason": "Investigated by secops: false positive on test payload"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "released"
    assert data["agent_id"] == "agent-quarantined"

    # Agent status is now NORMAL
    assert fake_reg.agents["agent-quarantined"].status == AgentStatus.NORMAL

    # Audit ledger contains the release entry with human source
    lines = [json.loads(line) for line in ledger.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    release_entries = [e for e in lines if e.get("record", {}).get("action") == "RELEASE"]
    assert len(release_entries) == 1
    rec = release_entries[0]["record"]
    assert rec["source"] == "human"
    assert rec["agent_id"] == "agent-quarantined"
    assert "Investigated by secops" in rec["reason"]


def test_gate_sourced_quarantine_is_still_quarantined_after_twice_duration():
    """Test invariant: simulator recovery loop NEVER restores gate-applied quarantine."""
    async def _test():
        fake_reg = FakeRegistryForRelease()
        # Set agent to quarantined with gate source
        await fake_reg.update_status("agent-quarantined", AgentStatus.QUARANTINED, source="gate")

        mock_event_bus = AsyncMock()
        mock_monitor = AsyncMock()

        # Create simulator with 0.2 second quarantine duration
        sim = DynamicTrafficSimulator(
            registry=fake_reg,
            monitor=mock_monitor,
            event_bus=mock_event_bus,
            interval_seconds=0.05,
            quarantine_duration_seconds=0.2,
        )

        sim.running = True
        task = asyncio.create_task(sim._recovery_loop())

        # Wait for twice the quarantine duration (0.4s + buffer)
        await asyncio.sleep(0.5)

        # Stop loop
        sim.running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Agent MUST still be QUARANTINED!
        agent = await fake_reg.get_agent("agent-quarantined")
        assert agent.status == AgentStatus.QUARANTINED, (
            f"Expected agent-quarantined to remain QUARANTINED, but found status={agent.status}"
        )

    asyncio.run(_test())
