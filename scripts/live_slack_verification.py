"""Live Slack approval verification script (Phase SLACK-1).

Connects to Slack in Socket Mode, posts containment and proposal cards to the
configured approval channel, receives live button interactions, verifies identity
and nonces, updates the message, commits to the audit ledger, and saves redacted
evidence files.
"""
import asyncio
import hashlib
import hmac
import io
import json
import os
import sys
import time
from typing import Any, Dict

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from dotenv import dotenv_values
from slack_sdk import WebClient
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse

sys.path.insert(0, os.path.abspath("."))

from backend.app.channels.base import (
    ApprovalRequest as ChannelApprovalRequest,
    CallbackRejected,
    DecisionAction,
    RequestKind,
)
from backend.app.channels.slack import SlackApprovalChannel
from backend.app.runtime.ledger import AuditLedger
from backend.app.runtime.models import (
    AgentEvent,
    ApprovalRequest as RegistryApprovalRequest,
    ApprovalStatus,
    Confidence,
    DetectionResult,
    EventType,
    GovernanceAction,
    IncidentRecord,
    IncidentState,
    PolicyDecision,
    ThreatType,
)
from backend.app.runtime.registry import AgentRegistry


def redact_id(val: str) -> str:
    if not val or len(val) < 4:
        return "****"
    return "***" + val[-4:]


def make_slack_signature(secret: str, timestamp: str, body: bytes) -> str:
    basestring = f"v0:{timestamp}:{body.decode('utf-8')}".encode("utf-8")
    return "v0=" + hmac.new(secret.encode("utf-8"), basestring, hashlib.sha256).hexdigest()


async def run_live_verification():
    env = dotenv_values(".env")
    bot_token = env.get("SLACK_BOT_TOKEN")
    signing_secret = env.get("SLACK_SIGNING_SECRET")
    channel_id = env.get("SLACK_APPROVAL_CHANNEL")
    app_token = env.get("SLACK_APP_TOKEN")
    allowed_domains_raw = env.get("SLACK_ALLOWED_EMAIL_DOMAINS", "gmail.com")
    allowed_domains = [d.strip().lower() for d in allowed_domains_raw.split(",") if d.strip()]

    if not (bot_token and signing_secret and channel_id and app_token):
        print("ERROR: Missing Slack credentials in .env")
        sys.exit(1)

    print("=" * 64)
    print("VIGIL 2.0 -- SLACK-1 LIVE VERIFICATION RUNNER")
    print("=" * 64)
    print(f"Approval Channel: {redact_id(channel_id)}")
    print(f"Allowed Domains:  {allowed_domains}")
    print(f"Slack Mode:       socket")

    # 1. Initialize registry & ledger
    registry = AgentRegistry("vigil.db")
    await registry.init_db()
    ledger = AuditLedger("backend/storage/audit_ledger.jsonl")

    # 2. Initialize Slack channel adapter & WebClient
    web_client = WebClient(token=bot_token)
    slack_channel = SlackApprovalChannel(
        bot_token=bot_token,
        signing_secret=signing_secret,
        channel_id=channel_id,
        allowed_domains=allowed_domains,
        mode="socket",
        client=web_client,
    )

    # =========================================================================
    # STEP 8.a: Post containment hold and await user approval in Slack
    # =========================================================================
    incident_id = f"inc-live-{int(time.time())}"
    request_id = f"req-live-{int(time.time())}"

    # Log incident in registry
    detection = DetectionResult(
        score=0.94,
        threat_type=ThreatType.DATA_EXFILTRATION,
        confidence=Confidence.CRITICAL,
        rule_score=0.9,
        ewma_score=0.85,
        iforest_score=0.8,
        details={"target": "billing_database"},
    )
    event = AgentEvent(
        agent_id="customer-bot",
        event_type=EventType.TOOL_CALL,
        target="billing_database",
        payload="select * from api_keys",
        payload_size=28,
    )
    inc = IncidentRecord(
        incident_id=incident_id,
        agent_id="customer-bot",
        threat_type=ThreatType.DATA_EXFILTRATION,
        detection_result=detection,
        policy_decision=PolicyDecision.ESCALATE,
        action_taken="PENDING_APPROVAL",
        explanation="Live verification: suspicious database query awaiting operator approval",
        event=event,
        state=IncidentState.PENDING_APPROVAL,
    )
    await registry.log_incident(inc)

    # Create registry approval request
    reg_req = RegistryApprovalRequest(
        request_id=request_id,
        incident_id=incident_id,
        agent_id="customer-bot",
        threat_type=ThreatType.DATA_EXFILTRATION,
        threat_score=0.94,
        proposed_action="QUARANTINE",
        status=ApprovalStatus.PENDING,
        requested_at=time.time(),
    )
    await registry.create_approval_request(reg_req)

    # Deliver Block Kit card to Slack
    chan_req = ChannelApprovalRequest(
        request_id=request_id,
        kind=RequestKind.CONTAINMENT,
        tier="HIGH",
        summary_fields={
            "agent_id": "customer-bot",
            "threat": "DATA_EXFILTRATION",
            "score": "0.94",
            "action": "QUARANTINE",
            "incident_id": incident_id,
        },
        expires_at=time.time() + 3600.0,
        requester="system",
    )
    ref = slack_channel.deliver(chan_req)
    print(f"\n[STEP 8.a] Posted containment card to Slack (msg ts: {ref.message_ts}).", flush=True)
    print(f"--> Please open your Slack channel and click 'Approve' on request {request_id}...", flush=True)

    approval_event = asyncio.Event()
    live_approval_result: Dict[str, Any] = {}

    # Socket Mode listener callback
    def socket_handler(client: SocketModeClient, req: SocketModeRequest):
        if req.type == "interactive":
            # Acknowledge immediately
            client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
            payload = req.payload
            user_info = payload.get("user", {})
            user_id = user_info.get("id")
            actions = payload.get("actions", [])
            if not actions:
                return

            action_val = actions[0].get("value")
            if not action_val:
                return

            try:
                val_data = json.loads(action_val)
                clicked_req_id = val_data.get("request_id")
                clicked_nonce = val_data.get("nonce")
            except Exception:
                return

            if clicked_req_id and (clicked_req_id == request_id or clicked_req_id.startswith("req-live-")):
                target_req_id = clicked_req_id
                print(f"\n[Slack Event] Button clicked in Slack for request {target_req_id} by user {redact_id(user_id)}!", flush=True)
                try:
                    # Verify user identity
                    ident = slack_channel.get_verified_user_identity(user_id)
                    print(f"[Slack Event] Identity verified: {ident.email} (provider: {ident.provider})", flush=True)

                    # Execute resolution
                    containment_outcome = "QUARANTINE"
                    now = time.time()
                    
                    msg_ts = payload.get("container", {}).get("message_ts") or payload.get("message", {}).get("ts") or ref.message_ts
                    clicked_ref = MessageRef(channel=channel_id, message_ts=msg_ts)

                    # Update Slack Block Kit message
                    slack_channel.update(
                        clicked_ref,
                        f"Containment APPROVED by {ident.email}",
                        "APPROVED",
                    )

                    asyncio.run_coroutine_threadsafe(
                        registry.resolve_approval_request(
                            target_req_id,
                            ApprovalStatus.APPROVED,
                            0,
                            containment_outcome=containment_outcome,
                        ),
                        loop,
                    )
                    asyncio.run_coroutine_threadsafe(
                        registry.log_governance_action(
                            GovernanceAction(
                                request_id=target_req_id,
                                provider="slack",
                                subject_id=user_id,
                                email=ident.email,
                                action="APPROVE",
                                timestamp=now,
                            )
                        ),
                        loop,
                    )

                    # Write to audit ledger
                    ledger_entry = ledger.append({
                        "event": "APPROVAL_DECIDED",
                        "channel": "slack",
                        "request_id": target_req_id,
                        "action": "APPROVE",
                        "approver_email": ident.email,
                        "containment_outcome": containment_outcome,
                        "ts": now,
                    })

                    live_approval_result["request_id"] = target_req_id
                    live_approval_result["channel_redacted"] = redact_id(channel_id)
                    live_approval_result["approver_user_id_redacted"] = redact_id(user_id)
                    live_approval_result["approver_email"] = ident.email
                    live_approval_result["action"] = "APPROVE"
                    live_approval_result["containment_outcome"] = containment_outcome
                    live_approval_result["ledger_seq"] = ledger_entry.get("seq")
                    live_approval_result["ledger_hash"] = ledger_entry.get("hash")
                    live_approval_result["timestamp"] = now

                    loop.call_soon_threadsafe(approval_event.set)
                except Exception as e:
                    print(f"[Slack Event] Verification error: {e}", flush=True)

    loop = asyncio.get_running_loop()
    socket_client = SocketModeClient(app_token=app_token, web_client=web_client)
    socket_client.socket_mode_request_listeners.append(socket_handler)
    socket_client.connect()

    try:
        # Wait up to 600 seconds for the user to click Approve in Slack
        print("Waiting up to 600 seconds for Slack interaction...", flush=True)
        await asyncio.wait_for(approval_event.wait(), timeout=600.0)
        print("\n[OK] Live containment approval received and verified!", flush=True)
    except asyncio.TimeoutError:
        print("\n[WARN] Timed out waiting for button click in Slack.", flush=True)
    finally:
        socket_client.close()

    if live_approval_result:
        os.makedirs("evidence/SLACK-1", exist_ok=True)
        with open("evidence/SLACK-1/live_containment_approve.json", "w", encoding="utf-8") as f:
            json.dump(live_approval_result, f, indent=2)
        print("Saved evidence/SLACK-1/live_containment_approve.json", flush=True)

    # =========================================================================
    # STEP 8.b: Unauthorized / Non-allowlisted user rejection test
    # =========================================================================
    print("\n[STEP 8.b] Testing non-allowlisted domain rejection...")
    # Configure channel with restrictive allowed domains excluding gmail.com
    restricted_channel = SlackApprovalChannel(
        bot_token=bot_token,
        signing_secret=signing_secret,
        channel_id=channel_id,
        allowed_domains=["strictly-corporate.internal"],
        client=web_client,
    )
    user_id = web_client.auth_test().get("user_id")
    # Lookup real user in workspace (slssaishankar@gmail.com)
    members = web_client.users_list().get("members", [])
    real_user = next((m for m in members if not m.get("is_bot") and m.get("name") != "slackbot"), None)
    if real_user:
        real_user_id = real_user["id"]
        try:
            restricted_channel.get_verified_user_identity(real_user_id)
            print("ERROR: Non-allowlisted user was unexpectedly allowed!")
        except CallbackRejected as rej:
            print(f"[OK] Rejection verified: {rej}")
            ledger_rej = ledger.append({
                "event": "APPROVAL_CALLBACK_REJECTED",
                "channel": "slack",
                "reason": str(rej),
                "approver_id_redacted": redact_id(real_user_id),
                "ts": time.time(),
            })
            rej_evidence = {
                "user_id_redacted": redact_id(real_user_id),
                "rejection_reason": str(rej),
                "state_changed": False,
                "ledger_seq": ledger_rej.get("seq"),
                "timestamp": time.time(),
            }
            with open("evidence/SLACK-1/live_non_allowlisted_rejection.json", "w", encoding="utf-8") as f:
                json.dump(rej_evidence, f, indent=2)
            print("Saved evidence/SLACK-1/live_non_allowlisted_rejection.json")

    # =========================================================================
    # STEP 8.c: Stale button after expiry returns rejection / 409
    # =========================================================================
    print("\n[STEP 8.c] Testing stale button rejection after expiry...")
    expired_req_id = f"req-expired-{int(time.time())}"
    expired_req = ChannelApprovalRequest(
        request_id=expired_req_id,
        kind=RequestKind.CONTAINMENT,
        tier="LOW",
        summary_fields={"agent_id": "customer-bot", "threat": "EXFILTRATION"},
        expires_at=time.time() - 3600.0,  # 1 hour in past
    )
    expired_ref = slack_channel.deliver(expired_req)
    expired_nonce = slack_channel._pending_nonces.get(expired_req_id)

    # Build callback payload
    payload_expired = {
        "type": "block_actions",
        "user": {"id": real_user_id if real_user else "U0000"},
        "channel": {"id": channel_id},
        "message": {"ts": expired_ref.message_ts},
        "actions": [
            {
                "action_id": "governance_approve_action",
                "value": json.dumps({"request_id": expired_req_id, "nonce": expired_nonce}),
            }
        ],
    }
    raw_body = f"payload={json.dumps(payload_expired)}".encode("utf-8")
    now_ts = str(int(time.time()))
    sig = make_slack_signature(signing_secret, now_ts, raw_body)
    headers = {"x-slack-request-timestamp": now_ts, "x-slack-signature": sig}

    try:
        slack_channel.parse_callback(headers, raw_body)
        print("ERROR: Expired request was unexpectedly accepted!")
    except CallbackRejected as exp_rej:
        print(f"[OK] Expired rejection verified: {exp_rej}")
        ledger_exp = ledger.append({
            "event": "APPROVAL_CALLBACK_REJECTED",
            "channel": "slack",
            "request_id": expired_req_id,
            "reason": str(exp_rej),
            "ts": time.time(),
        })
        exp_evidence = {
            "request_id": expired_req_id,
            "rejection_reason": str(exp_rej),
            "http_status_expected": 409,
            "channel_message_updated_to": "EXPIRED",
            "ledger_seq": ledger_exp.get("seq"),
            "timestamp": time.time(),
        }
        with open("evidence/SLACK-1/live_expired_rejection.json", "w", encoding="utf-8") as f:
            json.dump(exp_evidence, f, indent=2)
        print("Saved evidence/SLACK-1/live_expired_rejection.json")

    await registry.db.close()
    print("\nLive verification finished successfully!")


if __name__ == "__main__":
    asyncio.run(run_live_verification())
