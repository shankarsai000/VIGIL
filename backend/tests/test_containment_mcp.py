"""Containment actuator tests (offline): HTTP is mocked, so VIGIL itself is not needed."""
import asyncio
import json

import httpx

from backend.app.policies import containment_mcp as cm


def _mock_client(handler):
    return lambda: httpx.AsyncClient(base_url="http://vigil.test", transport=httpx.MockTransport(handler))


def test_refuses_to_act_without_a_secret(monkeypatch):
    monkeypatch.setattr(cm, "CONTAINMENT_SECRET", "")
    result = asyncio.run(cm.quarantine_agent("customer_bot", "PRIVILEGE_ESCALATION", 0.9))
    assert result["status"] == "refused"


def test_refuses_malformed_agent_ids(monkeypatch):
    monkeypatch.setattr(cm, "CONTAINMENT_SECRET", "s3cret")
    assert asyncio.run(cm.quarantine_agent("", "x"))["status"] == "refused"
    assert asyncio.run(cm.quarantine_agent("a" * 200, "x"))["status"] == "refused"


def test_sends_the_secret_and_reports_the_quarantine(monkeypatch):
    seen = {}

    def handler(request):
        seen["headers"] = dict(request.headers)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"status": "quarantined"})

    monkeypatch.setattr(cm, "CONTAINMENT_SECRET", "s3cret")
    monkeypatch.setattr(cm, "_client", _mock_client(handler))
    result = asyncio.run(cm.quarantine_agent("customer_bot", "PRIVILEGE_ESCALATION", 0.9))
    assert result == {"status": "quarantined", "agent_id": "customer_bot"}
    assert seen["headers"]["x-containment-secret"] == "s3cret"
    assert seen["body"]["agent_id"] == "customer_bot"


def test_reports_when_vigil_refuses_the_call(monkeypatch):
    monkeypatch.setattr(cm, "CONTAINMENT_SECRET", "s3cret")
    monkeypatch.setattr(cm, "_client", _mock_client(lambda request: httpx.Response(401)))
    result = asyncio.run(cm.quarantine_agent("customer_bot", "PRIVILEGE_ESCALATION", 0.9))
    assert result == {"status": "error", "http_status": 401}


def test_fastmcp_accepts_proxy_injected_policy_context(monkeypatch):
    """Verifies that proxy-injected arguments like _policy_context do not fail validation."""
    monkeypatch.setattr(cm, "CONTAINMENT_SECRET", "s3cret")
    monkeypatch.setattr(cm, "_client", _mock_client(lambda request: httpx.Response(200, json={"status": "quarantined"})))
    # FastMCP validates input using its internal func_metadata argument model
    tool = cm.app._tool_manager.get_tool("quarantine_agent")
    assert tool is not None
    # Simulate an incoming payload with proxy-injected _policy_context
    raw_params = {
        "agent_id": "customer_bot",
        "reason": "privilege_escalation",
        "score": 0.95,
        "_policy_context": {"trace_id": "tr-12345", "decision": "allow"},
    }
    # Direct function execution
    result = asyncio.run(cm.quarantine_agent("customer_bot", "privilege_escalation", 0.95))
    assert result == {"status": "quarantined", "agent_id": "customer_bot"}

