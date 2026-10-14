"""Route protection tests (offline). The app runs without its lifespan, so no Postgres, Redis, or Telegram is needed."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.app.api import security
from backend.app.runtime.ledger import AuditLedger
from backend.main import app

OP_KEY = "op-key-0123456789"
CS_SECRET = "containment-secret-abcdef"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setattr(security, "settings", SimpleNamespace(operator_api_key=OP_KEY, containment_secret=CS_SECRET))


class FakeRegistry:
    def __init__(self, known=("customer_bot",)):
        self.known = set(known)
        self.statuses = {}

    async def get_agent(self, agent_id):
        if agent_id not in self.known:
            return None
        return SimpleNamespace(model_dump=lambda mode="json": {"agent_id": agent_id})

    async def update_status(self, agent_id, status):
        self.statuses[agent_id] = status


async def _noop_observe(event):
    return None


def test_write_routes_refuse_when_no_operator_key_is_configured(client, monkeypatch):
    monkeypatch.setattr(security, "settings", SimpleNamespace(operator_api_key="", containment_secret=""))
    response = client.post("/attack/prompt_injection")
    assert response.status_code == 503


def test_write_routes_reject_a_wrong_operator_key(client, keys):
    response = client.post("/attack/prompt_injection", headers={"X-VIGIL-Operator-Key": "wrong"})
    assert response.status_code == 401


def test_write_routes_accept_the_right_key(client, keys):
    app.state.monitor = SimpleNamespace(observe=_noop_observe)
    response = client.post("/attack/prompt_injection", headers={"X-VIGIL-Operator-Key": OP_KEY})
    assert response.status_code == 200
    assert response.json()["status"] == "attack_fired"


def test_the_websocket_refuses_connections_without_the_operator_key(client, keys):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?key=wrong") as ws:
            ws.receive_text()


def test_the_containment_callback_requires_its_secret(client, keys):
    app.state.registry = FakeRegistry()
    app.state.event_bus = asyncio.Queue()
    body = {"agent_id": "customer_bot", "reason": "PRIVILEGE_ESCALATION"}
    assert client.post("/internal/containment/quarantine", json=body).status_code == 401
    wrong = client.post("/internal/containment/quarantine", json=body, headers={"X-Containment-Secret": "nope"})
    assert wrong.status_code == 401


def test_the_containment_callback_refuses_when_no_secret_is_configured(client, monkeypatch):
    monkeypatch.setattr(security, "settings", SimpleNamespace(operator_api_key=OP_KEY, containment_secret=""))
    response = client.post("/internal/containment/quarantine", json={"agent_id": "customer_bot"},
                           headers={"X-Containment-Secret": "anything"})
    assert response.status_code == 503


def test_the_containment_callback_quarantines_a_known_agent_and_broadcasts(client, keys):
    registry = FakeRegistry()
    app.state.registry = registry
    app.state.event_bus = asyncio.Queue()
    response = client.post("/internal/containment/quarantine", json={"agent_id": "customer_bot", "reason": "x"},
                           headers={"X-Containment-Secret": CS_SECRET})
    assert response.status_code == 200
    assert registry.statuses["customer_bot"].value == "QUARANTINED"
    assert app.state.event_bus.qsize() == 1


def test_the_containment_callback_rejects_unknown_agents(client, keys):
    app.state.registry = FakeRegistry(known=())
    app.state.event_bus = asyncio.Queue()
    response = client.post("/internal/containment/quarantine", json={"agent_id": "ghost"},
                           headers={"X-Containment-Secret": CS_SECRET})
    assert response.status_code == 404


def test_the_audit_verify_route_reports_a_clean_ledger(client, tmp_path):
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    ledger.append({"n": 1})
    ledger.append({"n": 2})
    app.state.gate = SimpleNamespace(ledger=ledger)
    body = client.get("/audit/verify").json()
    assert body["ok"] is True and body["entries"] == 2 and body["bad_seq"] is None
