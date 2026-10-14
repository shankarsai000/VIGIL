"""ArmorIQ gate tests (offline). The SDK is replaced by a fake that raises the real ArmorIQ exception classes."""
import asyncio
import json
import time
from types import SimpleNamespace

import pytest
from armoriq_sdk import ArmorIQException, PolicyBlockedException, PolicyHoldException

from backend.app.policies import armoriq_gate as gate_mod
from backend.app.policies.armoriq_gate import CONTAINMENT_TOOL, ArmorIQGate
from backend.app.runtime.models import PolicyDecision, ThreatContext, ThreatType

MCP = "vigil-containment"
APPROVED, DENIED, ESCALATE = PolicyDecision.APPROVED, PolicyDecision.DENIED, PolicyDecision.ESCALATE


class FakeRegistry:
    def __init__(self):
        self.entries = []

    async def log_policy_decision(self, entry):
        self.entries.append(entry)

    async def get_audit_log(self, limit=50):
        return self.entries[:limit]


class FakeSDK:
    def __init__(self, result=None, invoke_exc=None):
        self.result = result
        self.invoke_exc = invoke_exc
        self.plan = None
        self.policy = None
        self.calls = []

    def capture_plan(self, llm, prompt, plan, metadata=None):
        self.plan = plan
        return {"plan": plan}

    def get_intent_token(self, captured, policy=None, validity_seconds=60.0):
        self.policy = policy
        return "token-123"

    def invoke_with_policy(self, mcp, action, token, params=None, options=None):
        self.calls.append({"mcp": mcp, "action": action, "params": params, "options": options})
        if self.invoke_exc is not None:
            raise self.invoke_exc
        return self.result


def cfg(tmp_path, mode="live", key="ak_test_0123456789", email="ops@example.com"):
    return SimpleNamespace(
        armoriq_mode=mode, armoriq_api_key=key, armoriq_user_email=email,
        armoriq_agent_id="vigil-containment", armoriq_containment_mcp_id=MCP,
        armoriq_use_production=True, armoriq_token_validity_seconds=300,
        audit_ledger_path=str(tmp_path / "ledger.jsonl"),
    )


def threat(action="QUARANTINE", score=0.92):
    return ThreatContext(agent_id="customer_bot", threat_type=ThreatType.PRIVILEGE_ESCALATION,
                         score=score, proposed_action=action, timestamp=time.time())


def make_live(tmp_path, sdk):
    gate = ArmorIQGate(cfg(tmp_path), FakeRegistry(), client_factory=lambda: sdk)
    asyncio.run(gate.startup())
    return gate


def decide(gate, ctx):
    return asyncio.run(gate.evaluate_policy(ctx))


def test_disabled_mode_never_contains_anything(tmp_path):
    gate = ArmorIQGate(cfg(tmp_path, mode="disabled"), FakeRegistry())
    asyncio.run(gate.startup())
    assert decide(gate, threat("QUARANTINE")) is ESCALATE
    assert decide(gate, threat("ALERT")) is APPROVED


def test_live_approval_is_a_governed_call_with_no_approval_wait(tmp_path):
    sdk = FakeSDK(result=SimpleNamespace(status="success"))
    gate = make_live(tmp_path, sdk)
    assert decide(gate, threat()) is APPROVED
    call = sdk.calls[0]
    assert call["mcp"] == MCP and call["action"] == CONTAINMENT_TOOL
    assert call["params"]["agent_id"] == "customer_bot"
    assert call["options"].wait_for_approval is False
    assert call["options"].user_email == "ops@example.com"
    assert sdk.policy == {"allow": [f"{MCP}/{CONTAINMENT_TOOL}"], "deny": []}
    assert sdk.plan["steps"][0]["action"] == CONTAINMENT_TOOL


def test_a_hold_becomes_escalation_not_containment(tmp_path):
    sdk = FakeSDK(invoke_exc=PolicyHoldException("approval required"))
    assert decide(make_live(tmp_path, sdk), threat()) is ESCALATE


def test_an_explicit_policy_denial_is_denied(tmp_path):
    sdk = FakeSDK(invoke_exc=PolicyBlockedException("denied", reason="deny rule"))
    assert decide(make_live(tmp_path, sdk), threat()) is DENIED


def test_a_platform_error_fails_closed(tmp_path):
    sdk = FakeSDK(invoke_exc=ArmorIQException("token service unavailable"))
    assert decide(make_live(tmp_path, sdk), threat()) is ESCALATE


def test_an_unexpected_exception_fails_closed(tmp_path):
    sdk = FakeSDK(invoke_exc=RuntimeError("boom"))
    assert decide(make_live(tmp_path, sdk), threat()) is ESCALATE


def test_a_tool_error_result_is_not_an_approval(tmp_path):
    sdk = FakeSDK(result=SimpleNamespace(status="error"))
    assert decide(make_live(tmp_path, sdk), threat()) is ESCALATE


def test_auth_failures_no_longer_fall_back_to_local_thresholds(tmp_path):
    # The old gate approved high-score containment after a 401/403. Now every ArmorIQ error escalates.
    sdk = FakeSDK(invoke_exc=ArmorIQException("401 unauthorized"))
    gate = make_live(tmp_path, sdk)
    for score in (0.99, 0.9):
        assert decide(gate, threat(score=score)) is ESCALATE


def test_live_mode_refuses_to_start_without_a_real_key_and_principal(tmp_path):
    for bad in (cfg(tmp_path, key=""), cfg(tmp_path, key="mock"), cfg(tmp_path, email="")):
        with pytest.raises(RuntimeError):
            asyncio.run(ArmorIQGate(bad, FakeRegistry()).startup())


def test_local_demo_is_labelled_and_keeps_the_old_thresholds(tmp_path):
    gate = ArmorIQGate(cfg(tmp_path, mode="local-demo"), FakeRegistry())
    assert decide(gate, threat(score=0.9)) is APPROVED
    assert decide(gate, threat(score=0.7)) is ESCALATE
    assert decide(gate, threat(score=0.4)) is APPROVED
    asyncio.run(gate.log_audit(threat(score=0.9), APPROVED, "QUARANTINE"))
    row = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[0])
    assert row["record"]["enforcement"] == "local-demo (NOT ArmorIQ)"


def test_a_slow_authorization_times_out_into_escalation(tmp_path, monkeypatch):
    monkeypatch.setattr(gate_mod, "AUTHORIZATION_TIMEOUT_S", 0.05)

    class SlowSDK(FakeSDK):
        def invoke_with_policy(self, *args, **kwargs):
            time.sleep(0.5)
            return SimpleNamespace(status="success")

    assert decide(make_live(tmp_path, SlowSDK()), threat()) is ESCALATE


def test_non_containment_proposals_need_no_authority_and_no_network(tmp_path):
    sdk = FakeSDK(invoke_exc=RuntimeError("must not be called"))
    assert decide(make_live(tmp_path, sdk), threat("ALERT")) is APPROVED
    assert sdk.calls == []


def test_every_decision_is_written_to_the_ledger_and_the_registry(tmp_path):
    gate = make_live(tmp_path, FakeSDK(result=SimpleNamespace(status="success")))
    ctx = threat()
    decision = decide(gate, ctx)
    asyncio.run(gate.log_audit(ctx, decision, "QUARANTINE"))
    result = gate.ledger.verify()
    assert result.ok and result.entries == 1
    assert gate.registry.entries[0].decision is APPROVED


def test_human_approval_unlocks_local_demo_only(tmp_path):
    local = ArmorIQGate(cfg(tmp_path, mode="local-demo"), FakeRegistry())
    assert asyncio.run(local.authorize_containment(threat(score=0.4), human_approved=True)) is APPROVED
    assert asyncio.run(local.authorize_containment(threat(score=0.4), human_approved=False)) is APPROVED
    disabled = ArmorIQGate(cfg(tmp_path, mode="disabled"), FakeRegistry())
    asyncio.run(disabled.startup())
    assert asyncio.run(disabled.authorize_containment(threat(), human_approved=True)) is ESCALATE


def test_human_approval_cannot_override_an_armoriq_hold_or_denial(tmp_path):
    held = make_live(tmp_path, FakeSDK(invoke_exc=PolicyHoldException("approval required")))
    assert asyncio.run(held.authorize_containment(threat(), human_approved=True)) is ESCALATE
    denied = make_live(tmp_path, FakeSDK(invoke_exc=PolicyBlockedException("denied", reason="deny rule")))
    assert asyncio.run(denied.authorize_containment(threat(), human_approved=True)) is DENIED


class ExecRegistry:
    def __init__(self):
        self.statuses = {}
        self.incidents = []

    async def update_status(self, agent_id, status):
        self.statuses[agent_id] = status

    async def get_agent(self, agent_id):
        return SimpleNamespace(model_dump=lambda mode="json": {"agent_id": agent_id})

    async def log_incident(self, incident):
        self.incidents.append(incident)


def make_executor(gate):
    from backend.app.remediation.remediation import RemediationExecutor

    executor = RemediationExecutor.__new__(RemediationExecutor)
    executor.gate = gate
    executor.registry = ExecRegistry()
    executor.event_bus = asyncio.Queue()
    return executor


def incident():
    return SimpleNamespace(
        agent_id="customer_bot", incident_id="inc-1", threat_type=ThreatType.PRIVILEGE_ESCALATION,
        detection_result=SimpleNamespace(score=0.92),
        model_dump=lambda *args, **kwargs: {"incident_id": "inc-1"},
    )


def test_an_approved_quarantine_runs_when_the_gate_allows_it(tmp_path):
    executor = make_executor(ArmorIQGate(cfg(tmp_path, mode="local-demo"), FakeRegistry()))
    outcome = asyncio.run(executor.execute_human_approved(incident(), "QUARANTINE", approver="test"))
    assert outcome == "QUARANTINE"
    assert executor.registry.statuses["customer_bot"].value == "QUARANTINED"


def test_an_approval_does_not_contain_when_armoriq_holds(tmp_path):
    executor = make_executor(make_live(tmp_path, FakeSDK(invoke_exc=PolicyHoldException("approval required"))))
    outcome = asyncio.run(executor.execute_human_approved(incident(), "QUARANTINE", approver="test"))
    assert outcome == "NOT_CONTAINED (ESCALATE)"
    assert "customer_bot" not in executor.registry.statuses
