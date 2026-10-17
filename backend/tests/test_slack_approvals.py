"""Offline test suite for SLACK-1 Slack Approval Channel."""
import ast
import hashlib
import hmac
import importlib
import json
import time
from typing import Dict, Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from backend.app.channels.base import (
    ApprovalRequest,
    CallbackRejected,
    Decision,
    DecisionAction,
    MessageRef,
    RequestKind,
)
from backend.app.channels.slack import SlackApprovalChannel
from backend.app.config import settings
from backend.app.immune.workflow import (
    PolicyProposalRecord,
    STATUS_APPROVED,
    STATUS_EXPIRED,
    STATUS_PROPOSED,
    TIER_HIGH,
    TIER_LOW,
)
from backend.app.runtime.ledger import AuditLedger
from backend.app.runtime.models import (
    AgentEvent,
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

SECRET = "test-slack-signing-secret-1234567890"
CHANNEL_ID = "C12345678"
CORP_DOMAIN = "corp.example.com"


def make_slack_signature(secret: str, timestamp: str, body: bytes) -> str:
    sig_basestring = f"v0:{timestamp}:{body.decode('utf-8')}".encode("utf-8")
    computed = hmac.new(secret.encode("utf-8"), sig_basestring, hashlib.sha256).hexdigest()
    return f"v0={computed}"


@pytest.fixture
def fake_client():
    client = MagicMock()
    client.chat_postMessage = MagicMock(return_value={"ts": "1700000000.000100"})
    client.chat_update = MagicMock(return_value={"ok": True})
    client.users_info = MagicMock()
    return client


@pytest.fixture
def channel(fake_client):
    ch = SlackApprovalChannel(
        bot_token="xoxb-fake-token",
        signing_secret=SECRET,
        channel_id=CHANNEL_ID,
        allowed_domains=[CORP_DOMAIN],
        client=fake_client,
    )
    return ch


# ============================================================================
# 1. Signature Verification Tests
# ============================================================================

def test_signature_valid(channel):
    now = str(int(time.time()))
    raw_body = b'payload=%7B%22type%22%3A%22block_actions%22%7D'
    sig = make_slack_signature(SECRET, now, raw_body)
    headers = {"x-slack-request-timestamp": now, "x-slack-signature": sig}

    # Should not raise CallbackRejected
    assert channel.verify_signature(headers, raw_body) is True


def test_signature_tampered_body(channel):
    now = str(int(time.time()))
    raw_body = b'payload=%7B%22type%22%3A%22block_actions%22%7D'
    sig = make_slack_signature(SECRET, now, raw_body)
    tampered_body = b'payload=%7B%22type%22%3A%22tampered%22%7D'
    headers = {"x-slack-request-timestamp": now, "x-slack-signature": sig}

    with pytest.raises(CallbackRejected) as exc:
        channel.verify_signature(headers, tampered_body)
    assert "mismatch" in str(exc.value).lower()


def test_signature_stale_timestamp(channel):
    # Stale timestamp: 350 seconds ago
    stale = str(int(time.time()) - 350)
    raw_body = b'payload=%7B%22type%22%3A%22block_actions%22%7D'
    sig = make_slack_signature(SECRET, stale, raw_body)
    headers = {"x-slack-request-timestamp": stale, "x-slack-signature": sig}

    with pytest.raises(CallbackRejected) as exc:
        channel.verify_signature(headers, raw_body)
    assert "stale" in str(exc.value).lower()


def test_signature_missing_header(channel):
    raw_body = b'payload=%7B%22type%22%3A%22block_actions%22%7D'
    headers = {"x-slack-request-timestamp": str(int(time.time()))}

    with pytest.raises(CallbackRejected) as exc:
        channel.verify_signature(headers, raw_body)
    assert "missing" in str(exc.value).lower()


def test_signature_empty_secret():
    empty_channel = SlackApprovalChannel(
        bot_token="xoxb-fake",
        signing_secret="",
        channel_id=CHANNEL_ID,
        allowed_domains=[CORP_DOMAIN],
    )
    now = str(int(time.time()))
    raw_body = b'payload=%7B%7D'
    headers = {"x-slack-request-timestamp": now, "x-slack-signature": "v0=any"}

    with pytest.raises(CallbackRejected) as exc:
        empty_channel.verify_signature(headers, raw_body)
    assert "signing_secret" in str(exc.value).lower()


# ============================================================================
# 2. Identity Verification Tests
# ============================================================================

def test_identity_corporate_email_passes(channel, fake_client):
    fake_client.users_info.return_value = {
        "ok": True,
        "user": {
            "id": "U12345",
            "name": "alice",
            "is_restricted": False,
            "is_ultra_restricted": False,
            "is_stranger": False,
            "profile": {
                "email": f"alice@{CORP_DOMAIN}",
                "email_confirmed": True,
            },
        },
    }

    ident = channel.verify_user_identity("U12345")
    assert ident.verified is True
    assert ident.email == f"alice@{CORP_DOMAIN}"
    assert ident.subject_id == "U12345"


def test_identity_personal_domain_fails(channel, fake_client):
    fake_client.users_info.return_value = {
        "ok": True,
        "user": {
            "id": "U12345",
            "profile": {
                "email": "attacker@gmail.com",
                "email_confirmed": True,
            },
        },
    }

    with pytest.raises(CallbackRejected) as exc:
        channel.verify_user_identity("U12345")
    assert "domain" in str(exc.value).lower()


def test_identity_missing_email_fails(channel, fake_client):
    fake_client.users_info.return_value = {
        "ok": True,
        "user": {
            "id": "U12345",
            "profile": {},
        },
    }

    with pytest.raises(CallbackRejected) as exc:
        channel.verify_user_identity("U12345")
    assert "no email" in str(exc.value).lower()


def test_identity_guest_from_another_org_fails(channel, fake_client):
    fake_client.users_info.return_value = {
        "ok": True,
        "user": {
            "id": "U12345",
            "is_restricted": True,  # guest
            "profile": {
                "email": f"guest@{CORP_DOMAIN}",
            },
        },
    }

    with pytest.raises(CallbackRejected) as exc:
        channel.verify_user_identity("U12345")
    assert "guest" in str(exc.value).lower()


# ============================================================================
# 3. Nonce & Delivery Tests
# ============================================================================

def test_delivery_and_nonce_validation(channel, fake_client):
    req = ApprovalRequest(
        request_id="req-test-1",
        kind=RequestKind.CONTAINMENT,
        tier="LOW",
        summary_fields={
            "agent_id": "bot_alpha",
            "threat": "EXFILTRATION",
            "secret_param": "SUPER_SECRET_TOKEN_DO_NOT_LEAK",
        },
        expires_at=time.time() + 3600,
        requester="operator@corp.example.com",
    )

    ref = channel.deliver(req)
    assert ref.channel == CHANNEL_ID
    assert ref.message_ts == "1700000000.000100"

    # Confirm message body does not leak the raw argument value
    call_kwargs = fake_client.chat_postMessage.call_args.kwargs
    blocks_str = json.dumps(call_kwargs.get("blocks", []))
    assert "SUPER_SECRET_TOKEN_DO_NOT_LEAK" not in blocks_str

    # Extract the issued nonce from the active request state
    issued_nonce = channel._issued_nonces.get("req-test-1")
    assert issued_nonce is not None

    # Parsing callback with WRONG nonce fails
    fake_client.users_info.return_value = {
        "ok": True,
        "user": {
            "id": "U_BOB",
            "is_restricted": False,
            "profile": {"email": f"bob@{CORP_DOMAIN}", "email_confirmed": True},
        },
    }
    payload_bad_nonce = {
        "type": "block_actions",
        "user": {"id": "U_BOB"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "1700000000.000100"},
        "actions": [
            {
                "action_id": "governance_approve_action",
                "value": json.dumps({"request_id": "req-test-1", "nonce": "wrong-nonce"}),
            }
        ],
    }
    now = str(int(time.time()))
    body_bad = f"payload={json.dumps(payload_bad_nonce)}".encode("utf-8")
    sig_bad = make_slack_signature(SECRET, now, body_bad)
    headers_bad = {"x-slack-request-timestamp": now, "x-slack-signature": sig_bad}

    with pytest.raises(CallbackRejected) as exc:
        channel.parse_callback(headers_bad, body_bad)
    assert "nonce" in str(exc.value).lower()

    # Parsing with CORRECT nonce succeeds
    payload_good = {
        "type": "block_actions",
        "user": {"id": "U_BOB"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "1700000000.000100"},
        "actions": [
            {
                "action_id": "governance_approve_action",
                "value": json.dumps({"request_id": "req-test-1", "nonce": issued_nonce}),
            }
        ],
    }
    body_good = f"payload={json.dumps(payload_good)}".encode("utf-8")
    sig_good = make_slack_signature(SECRET, now, body_good)
    headers_good = {"x-slack-request-timestamp": now, "x-slack-signature": sig_good}

    decision = channel.parse_callback(headers_good, body_good)
    assert decision.request_id == "req-test-1"
    assert decision.action == DecisionAction.APPROVE
    assert decision.approver.email == f"bob@{CORP_DOMAIN}"

    # Replaying the SAME callback fails because nonce was consumed
    with pytest.raises(CallbackRejected) as exc:
        channel.parse_callback(headers_good, body_good)
    assert "nonce" in str(exc.value).lower()


# ============================================================================
# 4. Separation of Duties Tests
# ============================================================================

def test_separation_of_duties_requester_rejected(channel, fake_client):
    req = ApprovalRequest(
        request_id="req-prop-1",
        kind=RequestKind.POLICY_PROPOSAL,
        tier="LOW",
        summary_fields={"tool": "export_data"},
        expires_at=time.time() + 3600,
        requester=f"alice@{CORP_DOMAIN}",
    )
    channel.deliver(req)
    nonce = channel._issued_nonces["req-prop-1"]

    fake_client.users_info.return_value = {
        "ok": True,
        "user": {
            "id": "U_ALICE",
            "is_restricted": False,
            "profile": {"email": f"alice@{CORP_DOMAIN}", "email_confirmed": True},
        },
    }

    payload = {
        "type": "block_actions",
        "user": {"id": "U_ALICE"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "1700000000.000100"},
        "actions": [
            {
                "action_id": "governance_approve_action",
                "value": json.dumps({"request_id": "req-prop-1", "nonce": nonce}),
            }
        ],
    }
    now = str(int(time.time()))
    body = f"payload={json.dumps(payload)}".encode("utf-8")
    headers = {"x-slack-request-timestamp": now, "x-slack-signature": make_slack_signature(SECRET, now, body)}

    with pytest.raises(CallbackRejected) as exc:
        channel.parse_callback(headers, body)
    assert "separation of duties" in str(exc.value).lower()


# ============================================================================
# 5. Expiry & Ledger Tests
# ============================================================================

def test_expired_request_returns_rejection(channel, fake_client):
    req = ApprovalRequest(
        request_id="req-exp-1",
        kind=RequestKind.CONTAINMENT,
        tier="LOW",
        summary_fields={"agent": "bot"},
        expires_at=time.time() - 10,  # Expired
    )
    channel.deliver(req)
    nonce = channel._issued_nonces["req-exp-1"]

    fake_client.users_info.return_value = {
        "ok": True,
        "user": {
            "id": "U_BOB",
            "is_restricted": False,
            "profile": {"email": f"bob@{CORP_DOMAIN}", "email_confirmed": True},
        },
    }

    payload = {
        "type": "block_actions",
        "user": {"id": "U_BOB"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "1700000000.000100"},
        "actions": [
            {
                "action_id": "governance_approve_action",
                "value": json.dumps({"request_id": "req-exp-1", "nonce": nonce}),
            }
        ],
    }
    now = str(int(time.time()))
    body = f"payload={json.dumps(payload)}".encode("utf-8")
    headers = {"x-slack-request-timestamp": now, "x-slack-signature": make_slack_signature(SECRET, now, body)}

    with pytest.raises(CallbackRejected) as exc:
        channel.parse_callback(headers, body)
    assert "expired" in str(exc.value).lower()

    # Message should be updated to state EXPIRED
    fake_client.chat_update.assert_called()


# ============================================================================
# 6. Integration Endpoint & Idempotency Tests
# ============================================================================

def test_slack_interaction_endpoint_containment_and_idempotency(tmp_path, monkeypatch):
    import asyncio
    db_path = str(tmp_path / "test_slack_integ.db")
    registry = AgentRegistry(db_path)
    asyncio.run(registry.init_db())

    ledger = AuditLedger(str(tmp_path / "test_slack_ledger.jsonl"))

    app.state.registry = registry
    app.state.ledger = ledger
    app.state.event_bus = asyncio.Queue()

    # Setup incident and approval request in registry
    detection = DetectionResult(
        score=0.91,
        threat_type=ThreatType.DATA_EXFILTRATION,
        confidence=Confidence.HIGH,
        rule_score=0.9,
        ewma_score=0.8,
        iforest_score=0.7,
        details={},
    )
    event = AgentEvent(
        agent_id="bot_x",
        event_type=EventType.TOOL_CALL,
        target="data_export",
        payload="select",
        payload_size=6,
    )
    inc = IncidentRecord(
        incident_id="inc-slack-1",
        agent_id="bot_x",
        threat_type=ThreatType.DATA_EXFILTRATION,
        detection_result=detection,
        policy_decision=PolicyDecision.ESCALATE,
        action_taken="PENDING_APPROVAL",
        explanation="containment hold",
        event=event,
        state=IncidentState.PENDING_APPROVAL,
    )
    asyncio.run(registry.log_incident(inc))

    from backend.app.runtime.models import ApprovalRequest as RegistryApprovalRequest, ApprovalStatus
    req = RegistryApprovalRequest(
        request_id="req-integ-1",
        incident_id="inc-slack-1",
        agent_id="bot_x",
        threat_type=ThreatType.DATA_EXFILTRATION,
        threat_score=0.91,
        proposed_action="QUARANTINE",
        status=ApprovalStatus.PENDING,
        requested_at=time.time(),
    )
    asyncio.run(registry.create_approval_request(req))

    # Fake executor
    executed_actions = []
    class FakeExecutor:
        async def execute_human_approved(self, incident, action, approver="dashboard"):
            executed_actions.append((incident.incident_id, action, approver))
            return "QUARANTINE"

        async def _execute_log(self, incident):
            return None

    app.state.executor = FakeExecutor()

    # Fake Slack WebClient
    fake_client = MagicMock()
    fake_client.chat_postMessage = MagicMock(return_value={"ts": "12345.6789"})
    fake_client.chat_update = MagicMock(return_value={"ok": True})
    fake_client.users_info = MagicMock(return_value={
        "ok": True,
        "user": {
            "id": "U_OPERATOR",
            "is_restricted": False,
            "profile": {"email": f"operator@{CORP_DOMAIN}", "email_confirmed": True},
        },
    })

    slack_channel = SlackApprovalChannel(
        bot_token="xoxb-test",
        signing_secret=SECRET,
        channel_id=CHANNEL_ID,
        allowed_domains=[CORP_DOMAIN],
        client=fake_client,
    )

    # Register active request & pre-issue nonce
    chan_req = ApprovalRequest(
        request_id="req-integ-1",
        kind=RequestKind.CONTAINMENT,
        tier="LOW",
        summary_fields={"agent": "bot_x"},
        expires_at=time.time() + 3600,
    )
    slack_channel.deliver(chan_req)
    nonce = slack_channel._issued_nonces["req-integ-1"]

    app.state.slack_channel = slack_channel

    client = TestClient(app)

    # 1. First click: APPROVE
    payload = {
        "type": "block_actions",
        "user": {"id": "U_OPERATOR"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "12345.6789"},
        "actions": [
            {
                "action_id": "governance_approve_action",
                "value": json.dumps({"request_id": "req-integ-1", "nonce": nonce}),
            }
        ],
    }
    now = str(int(time.time()))
    raw_body = f"payload={json.dumps(payload)}".encode("utf-8")
    sig = make_slack_signature(SECRET, now, raw_body)
    headers = {
        "x-slack-request-timestamp": now,
        "x-slack-signature": sig,
        "content-type": "application/x-www-form-urlencoded",
    }

    res1 = client.post("/integrations/slack/interactions", content=raw_body, headers=headers)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["status"] == "APPROVED"
    assert data1["containment_outcome"] == "QUARANTINE"
    assert len(executed_actions) == 1
    assert executed_actions[0][2] == f"operator@{CORP_DOMAIN}"

    # Verify ledger was written
    entries = ledger.read_entries()
    dec_entries = [e for e in entries if e.get("event") == "APPROVAL_DECIDED"]
    assert len(dec_entries) == 1
    assert dec_entries[0]["approver_email"] == f"operator@{CORP_DOMAIN}"
    assert dec_entries[0]["containment_outcome"] == "QUARANTINE"

    # 2. Second click (idempotent duplicate request):
    # Register another nonce to test idempotency when request is already decided
    slack_channel._active_requests["req-integ-1"] = chan_req
    slack_channel._pending_nonces["req-integ-1"] = "nonce-2"
    payload2 = {
        "type": "block_actions",
        "user": {"id": "U_OPERATOR"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "12345.6789"},
        "actions": [
            {
                "action_id": "governance_approve_action",
                "value": json.dumps({"request_id": "req-integ-1", "nonce": "nonce-2"}),
            }
        ],
    }
    body2 = f"payload={json.dumps(payload2)}".encode("utf-8")
    sig2 = make_slack_signature(SECRET, now, body2)
    headers2 = {
        "x-slack-request-timestamp": now,
        "x-slack-signature": sig2,
        "content-type": "application/x-www-form-urlencoded",
    }

    res2 = client.post("/integrations/slack/interactions", content=body2, headers=headers2)
    assert res2.status_code == 200
    assert res2.json()["status"] == "APPROVED"
    assert res2.json()["idempotent"] is True
    # Ensure no second execution occurred!
    assert len(executed_actions) == 1

    asyncio.run(registry.db.close())


# ============================================================================
# 7. Two-Approver Rule Tests (Policy Proposals)
# ============================================================================

def test_two_approver_rule_for_high_tier_proposal(tmp_path, monkeypatch):
    import asyncio
    db_path = str(tmp_path / "test_proposals.db")
    registry = AgentRegistry(db_path)
    asyncio.run(registry.init_db())

    # Create HIGH tier proposal
    prop_id = "prop-high-999"
    proposal = PolicyProposalRecord(
        id=prop_id,
        status=STATUS_PROPOSED,
        agent_id="agent_high",
        tool="critical_wipe",
        impact_tier=TIER_HIGH,
        replay_json=json.dumps({"status": "ACCEPT", "coverage": 1.0, "false_block_upper": 0.004}),
        assumptions_json=json.dumps({"baseline": "clean"}),
        approvals_json="[]",
        created_at=time.time(),
        expires_at=time.time() + 72 * 3600,
    )
    asyncio.run(registry.create_policy_proposal(proposal))

    fake_client = MagicMock()
    fake_client.chat_postMessage = MagicMock(return_value={"ts": "222.333"})
    fake_client.chat_update = MagicMock(return_value={"ok": True})

    slack_channel = SlackApprovalChannel(
        bot_token="xoxb-test",
        signing_secret=SECRET,
        channel_id=CHANNEL_ID,
        allowed_domains=[CORP_DOMAIN],
        client=fake_client,
    )

    chan_req = ApprovalRequest(
        request_id=prop_id,
        kind=RequestKind.POLICY_PROPOSAL,
        tier="HIGH",
        summary_fields={"tool": "critical_wipe"},
        expires_at=time.time() + 3600,
    )
    slack_channel.deliver(chan_req)
    nonce1 = slack_channel._issued_nonces[prop_id]

    app.state.registry = registry
    app.state.ledger = AuditLedger(str(tmp_path / "test_m4_ledger.jsonl"))
    app.state.slack_channel = slack_channel

    client = TestClient(app)

    # First approver (Alice)
    fake_client.users_info = MagicMock(return_value={
        "ok": True,
        "user": {
            "id": "U_ALICE",
            "is_restricted": False,
            "profile": {"email": f"alice@{CORP_DOMAIN}", "email_confirmed": True},
        },
    })
    now = str(int(time.time()))
    payload1 = {
        "type": "block_actions",
        "user": {"id": "U_ALICE"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "222.333"},
        "actions": [{"action_id": "governance_approve_action", "value": json.dumps({"request_id": prop_id, "nonce": nonce1})}],
    }
    body1 = f"payload={json.dumps(payload1)}".encode("utf-8")
    res1 = client.post(
        "/integrations/slack/interactions",
        content=body1,
        headers={"x-slack-request-timestamp": now, "x-slack-signature": make_slack_signature(SECRET, now, body1)},
    )
    assert res1.status_code == 200
    p1 = asyncio.run(registry.get_policy_proposal(prop_id))
    assert p1["status"] == STATUS_PROPOSED
    approvals1 = json.loads(p1["approvals_json"])
    assert len(approvals1) == 1
    assert approvals1[0] == f"alice@{CORP_DOMAIN}"

    # Same approver (Alice) clicking again is ignored / duplicate
    slack_channel._active_requests[prop_id] = chan_req
    slack_channel._pending_nonces[prop_id] = "nonce-alice-again"
    payload_repeat = {
        "type": "block_actions",
        "user": {"id": "U_ALICE"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "222.333"},
        "actions": [{"action_id": "governance_approve_action", "value": json.dumps({"request_id": prop_id, "nonce": "nonce-alice-again"})}],
    }
    body_rep = f"payload={json.dumps(payload_repeat)}".encode("utf-8")
    res_rep = client.post(
        "/integrations/slack/interactions",
        content=body_rep,
        headers={"x-slack-request-timestamp": now, "x-slack-signature": make_slack_signature(SECRET, now, body_rep)},
    )
    assert res_rep.status_code == 200
    p_rep = asyncio.run(registry.get_policy_proposal(prop_id))
    approvals_rep = json.loads(p_rep["approvals_json"])
    assert len(approvals_rep) == 1  # Alice cannot approve twice!

    # Second distinct approver (Bob)
    fake_client.users_info = MagicMock(return_value={
        "ok": True,
        "user": {
            "id": "U_BOB",
            "is_restricted": False,
            "profile": {"email": f"bob@{CORP_DOMAIN}", "email_confirmed": True},
        },
    })
    slack_channel._active_requests[prop_id] = chan_req
    slack_channel._pending_nonces[prop_id] = "nonce-bob"
    payload2 = {
        "type": "block_actions",
        "user": {"id": "U_BOB"},
        "channel": {"id": CHANNEL_ID},
        "message": {"ts": "222.333"},
        "actions": [{"action_id": "governance_approve_action", "value": json.dumps({"request_id": prop_id, "nonce": "nonce-bob"})}],
    }
    body2 = f"payload={json.dumps(payload2)}".encode("utf-8")
    res2 = client.post(
        "/integrations/slack/interactions",
        content=body2,
        headers={"x-slack-request-timestamp": now, "x-slack-signature": make_slack_signature(SECRET, now, body2)},
    )
    assert res2.status_code == 200
    p2 = asyncio.run(registry.get_policy_proposal(prop_id))
    assert p2["status"] == STATUS_APPROVED
    approvals2 = json.loads(p2["approvals_json"])
    assert len(approvals2) == 2
    assert approvals2[1] == f"bob@{CORP_DOMAIN}"

    asyncio.run(registry.db.close())


# ============================================================================
# 8. Telegram Removal Verification
# ============================================================================

def test_telegram_removed_from_approval_paths():
    client = TestClient(app)

    # 1. Verify old routes return 410 Gone
    for route in [
        "/telegram/approvals",
        "/telegram/approvals/all",
        "/telegram/approvals/req-123/resolve",
        "/telegram/approvals/bulk-resolve",
    ]:
        res = client.get(route) if "resolve" not in route else client.post(route, json={"action": "approve"})
        assert res.status_code == 410, f"Route {route} did not return 410 Gone: {res.status_code}"

    # 2. Check AST / imports in approval path modules to guarantee zero telegram imports
    approval_modules = [
        "backend.app.channels.base",
        "backend.app.channels.slack",
        "backend.app.remediation.remediation",
        "backend.app.immune.workflow",
    ]

    for mod_name in approval_modules:
        mod = importlib.import_module(mod_name)
        file_path = mod.__file__
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=file_path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("telegram"), f"Module {mod_name} imports telegram: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert not node.module.startswith("telegram"), f"Module {mod_name} imports from telegram: {node.module}"
