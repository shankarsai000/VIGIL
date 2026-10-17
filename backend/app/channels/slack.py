"""Slack Approval Adapter for VIGIL Governed Runtime.

Implements the ApprovalChannel interface for Slack, providing:
- Cryptographic HMAC-SHA256 signature verification over raw callback bodies.
- Identity verification mapping Slack users to verified corporate email domains.
- Nonce-protected Block Kit interactive buttons with server-side nonce consumption.
- Anti-tampering and fail-closed security invariants.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from .base import (
    ApprovalChannel,
    ApprovalRequest,
    ApproverIdentity,
    CallbackRejected,
    Decision,
    DecisionAction,
    MessageRef,
    RequestKind,
)

logger = logging.getLogger("vigil.channels.slack")


class SlackApprovalChannel(ApprovalChannel):
    """Production and offline Slack adapter for governance approvals."""

    def __init__(
        self,
        bot_token: str = "",
        signing_secret: str = "",
        channel_id: str = "",
        approval_channel: str = "",
        allowed_domains: Optional[List[str]] = None,
        mode: str = "http",
        client: Optional[Any] = None,
    ):
        self.bot_token = bot_token
        self.signing_secret = signing_secret
        self.channel_id = channel_id or approval_channel
        self.allowed_domains = [d.strip().lower() for d in (allowed_domains or ["corp.internal", "example.com"])]
        self.mode = mode
        self.client = client or (WebClient(token=self.bot_token) if self.bot_token else None)
        
        # User identity cache: user_id -> (ApproverIdentity, expire_ts) (5 min TTL)
        self._user_cache: Dict[str, Tuple[ApproverIdentity, float]] = {}
        # Server-side issued nonces: request_id -> nonce
        self._pending_nonces: Dict[str, str] = {}
        # Active requests tracked in adapter: request_id -> ApprovalRequest
        self._active_requests: Dict[str, ApprovalRequest] = {}
        # Message references: request_id -> MessageRef
        self._message_refs: Dict[str, MessageRef] = {}

    @property
    def _issued_nonces(self) -> Dict[str, str]:
        return self._pending_nonces

    @property
    def is_configured(self) -> bool:
        """Indicates if Slack credentials and channel are configured."""
        return bool(self.bot_token and self.signing_secret and self.channel_id)

    def verify_request_signature(self, headers: Dict[str, str], raw_body: bytes) -> bool:
        """Verifies Slack HMAC-SHA256 request signature.
        
        Fails closed on missing headers, stale timestamp (>300s), or signature mismatch.
        Logs the failure reason but NEVER logs the raw body or signatures.
        """
        if not self.signing_secret:
            logger.warning("[Slack Auth] Refused callback: SLACK_SIGNING_SECRET is not configured.")
            raise CallbackRejected("SLACK_SIGNING_SECRET is not configured")

        # Normalize header keys to lowercase
        norm_headers = {k.lower(): v for k, v in headers.items()}
        timestamp = norm_headers.get("x-slack-request-timestamp")
        signature = norm_headers.get("x-slack-signature")

        if not timestamp or not signature:
            logger.warning("[Slack Auth] Refused callback: missing X-Slack-Request-Timestamp or X-Slack-Signature header.")
            raise CallbackRejected("Missing required Slack signature headers")

        try:
            ts_float = float(timestamp)
        except (ValueError, TypeError):
            logger.warning("[Slack Auth] Refused callback: unparseable timestamp.")
            raise CallbackRejected("Invalid timestamp header")

        now = time.time()
        if abs(now - ts_float) > 300.0:
            logger.warning("[Slack Auth] Refused callback: stale timestamp (delta > 300s).")
            raise CallbackRejected("Stale request timestamp (> 300s difference)")

        # Compute signature: v0:timestamp:body
        body_str = raw_body.decode("utf-8", errors="replace")
        sig_basestring = f"v0:{timestamp}:{body_str}".encode("utf-8")
        computed_sig = "v0=" + hmac.new(
            self.signing_secret.encode("utf-8"),
            sig_basestring,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(computed_sig, signature):
            logger.warning("[Slack Auth] Refused callback: signature verification failed.")
            raise CallbackRejected("Slack signature mismatch")

        return True

    def verify_signature(self, headers: Dict[str, str], raw_body: bytes) -> bool:
        """Alias for verify_request_signature."""
        return self.verify_request_signature(headers, raw_body)

    def verify_user_identity(self, user_id: str) -> ApproverIdentity:
        """Alias for get_verified_user_identity."""
        return self.get_verified_user_identity(user_id)

    def get_verified_user_identity(self, user_id: str) -> ApproverIdentity:
        """Resolves and validates a Slack user to a verified corporate approver identity.
        
        Enforces:
        - Presence of verified email.
        - Allowed domain check against SLACK_ALLOWED_EMAIL_DOMAINS.
        - Rejection of Slack Connect / guest accounts from other organizations.
        - Cache TTL of at most 5 minutes.
        """
        now = time.time()
        cached = self._user_cache.get(user_id)
        if cached:
            identity, expire_at = cached
            if now < expire_at:
                return identity

        if not self.client:
            raise CallbackRejected("Slack WebClient is not initialized")

        try:
            resp = self.client.users_info(user=user_id)
            user_data = resp.get("user") if isinstance(resp, dict) else getattr(resp, "data", {}).get("user")
        except Exception as e:
            logger.error("[Slack Identity] Failed to look up user '%s': %s", user_id, e)
            raise CallbackRejected(f"Slack users.info lookup failed: {e}")

        if not user_data:
            raise CallbackRejected(f"User '{user_id}' not found in Slack workspace")

        # 1. Reject Slack Connect and guest users
        if user_data.get("is_stranger", False) or user_data.get("is_restricted", False) or user_data.get("is_ultra_restricted", False):
            logger.warning("[Slack Identity] User '%s' is a guest/stranger account. Rejected.", user_id)
            raise CallbackRejected("Slack Connect / guest accounts cannot approve governance requests")

        # 2. Extract and verify email
        profile = user_data.get("profile", {})
        email = (profile.get("email") or "").strip().lower()
        if not email:
            logger.warning("[Slack Identity] User '%s' has no email on profile.", user_id)
            raise CallbackRejected("Slack user has no email address on profile")

        # Check domain allowlist
        domain = email.split("@")[-1].lower() if "@" in email else ""
        if domain not in self.allowed_domains:
            logger.warning("[Slack Identity] Email domain '%s' not in allowed domains %s", domain, self.allowed_domains)
            raise CallbackRejected(f"Email domain '{domain}' is not authorized to approve")

        identity = ApproverIdentity(
            provider="slack",
            subject_id=user_id,
            email=email,
            verified=True,
        )

        # Cache for 5 minutes (300 seconds)
        self._user_cache[user_id] = (identity, now + 300.0)
        return identity

    def deliver(self, request: ApprovalRequest) -> MessageRef:
        """Delivers a Block Kit governance approval card with interactive buttons."""
        # Generate and store server-side nonce
        nonce = secrets.token_hex(16)
        self._pending_nonces[request.request_id] = nonce
        self._active_requests[request.request_id] = request

        if not self.client or not self.channel_id:
            logger.info("[Slack Deliver] Offline/Disabled mode: delivery mocked for request %s", request.request_id)
            ref = MessageRef(channel=self.channel_id or "C_MOCK", message_ts=f"{time.time():.6f}")
            self._message_refs[request.request_id] = ref
            return ref

        # Format Block Kit message (strictly zero raw arguments or secrets)
        expiry_dt = datetime.fromtimestamp(request.expires_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🛡️ [{request.tier} IMPACT] {request.kind.value} APPROVAL",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Request ID:*\n`{request.request_id}`"},
                    {"type": "mrkdwn", "text": f"*Impact Tier:*\n`{request.tier}`"},
                    {"type": "mrkdwn", "text": f"*Agent ID:*\n`{request.summary.get('agent_id', 'unknown')}`"},
                    {"type": "mrkdwn", "text": f"*Target Tool / Action:*\n`{request.summary.get('tool', request.summary.get('action', 'N/A'))}`"},
                ],
            },
        ]

        # Add replay stats if policy proposal
        if request.kind == RequestKind.POLICY_PROPOSAL:
            cov = request.summary.get("coverage", 1.0) * 100
            fb = request.summary.get("false_block_upper", 0.0) * 100
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Attack Coverage:*\n`{cov:.1f}%`"},
                    {"type": "mrkdwn", "text": f"*95% Clopper-Pearson Bound:*\n`{fb:.3f}%`"},
                    {"type": "mrkdwn", "text": f"*Benign Baseline:*\n`{request.summary.get('benign_total', '600+')} samples`"},
                    {"type": "mrkdwn", "text": f"*Expires At:*\n`{expiry_dt}`"},
                ],
            })
        else:
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Reason:*\n{request.summary.get('reason', 'Threat containment escalation')}"},
                    {"type": "mrkdwn", "text": f"*Expires At:*\n`{expiry_dt}`"},
                ],
            })

        # Dashboard deep-link (login required)
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"🔗 <{request.dashboard_url}|*Open in VIGIL Dashboard (Operator Login Required)*>",
            },
        })

        # Interactive buttons: Value carries ONLY request_id and nonce (NEVER the decision)
        button_payload = json.dumps({"request_id": request.request_id, "nonce": nonce})
        blocks.append({
            "type": "actions",
            "block_id": f"gov_actions_{request.request_id}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve", "emoji": True},
                    "style": "primary",
                    "action_id": "governance_approve_action",
                    "value": button_payload,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Reject", "emoji": True},
                    "style": "danger",
                    "action_id": "governance_reject_action",
                    "value": button_payload,
                },
            ],
        })

        try:
            resp = self.client.chat_postMessage(
                channel=self.channel_id,
                text=f"[{request.tier}] {request.kind.value} Approval required for {request.summary.get('agent_id')}",
                blocks=blocks,
            )
            msg_ts = resp.get("ts") if isinstance(resp, dict) else getattr(resp, "data", {}).get("ts")
            ref = MessageRef(channel=self.channel_id, message_ts=msg_ts or f"{time.time():.6f}")
            self._message_refs[request.request_id] = ref
            return ref
        except Exception as e:
            logger.error("[Slack Deliver] Failed to post approval message: %s", e)
            raise

    def parse_callback(self, headers: Dict[str, str], raw_body: bytes) -> Decision:
        """Parses and validates interactive Slack button click callbacks."""
        # 1. Verify HMAC signature over raw body
        self.verify_request_signature(headers, raw_body)

        # 2. Parse URL-encoded form data (payload=...)
        body_str = raw_body.decode("utf-8", errors="replace")
        payload_dict = None

        if body_str.startswith("payload="):
            raw_json = urllib.parse.unquote_plus(body_str[len("payload=") :])
            try:
                payload_dict = json.loads(raw_json)
            except Exception as e:
                raise CallbackRejected(f"Failed to parse Slack URL-encoded payload: {e}")
        else:
            try:
                payload_dict = json.loads(body_str)
            except Exception as e:
                raise CallbackRejected(f"Failed to parse Slack JSON body: {e}")

        # 3. Extract user, action, and button value
        user_info = payload_dict.get("user", {})
        user_id = user_info.get("id")
        if not user_id:
            raise CallbackRejected("Missing user in Slack interaction payload")

        actions = payload_dict.get("actions", [])
        if not actions:
            raise CallbackRejected("No actions present in interaction payload")

        action_obj = actions[0]
        action_id = action_obj.get("action_id")
        raw_val = action_obj.get("value")

        if not raw_val:
            raise CallbackRejected("Missing button value in action payload")

        try:
            val_data = json.loads(raw_val)
            req_id = val_data.get("request_id")
            nonce = val_data.get("nonce")
        except Exception as e:
            raise CallbackRejected(f"Unparseable button value: {e}")

        if not req_id or not nonce:
            raise CallbackRejected("Button value missing request_id or nonce")

        # 4. Verify server-side issued nonce (prevents replay / forged buttons)
        expected_nonce = self._pending_nonces.get(req_id)
        if not expected_nonce:
            raise CallbackRejected("No pending nonce found for this request (already decided or expired)")

        if not hmac.compare_digest(expected_nonce, nonce):
            raise CallbackRejected("Nonce mismatch: button value does not match server-issued nonce")

        # Invalidate nonce on first use
        self._pending_nonces.pop(req_id, None)

        # 5. Resolve verified identity
        approver = self.get_verified_user_identity(user_id)

        # Check active request expiration and separation of duties if known
        active_req = self._active_requests.get(req_id)
        if active_req:
            if active_req.expires_at and time.time() > active_req.expires_at:
                ref = self._message_refs.get(req_id)
                if ref:
                    self.update(ref, "Request has expired.", "EXPIRED")
                raise CallbackRejected("Request has expired")
            if active_req.requester and approver.email:
                if active_req.requester.lower().strip() == approver.email.lower().strip():
                    raise CallbackRejected("Separation of duties: requester cannot approve their own proposal")

        # 6. Map action_id to DecisionAction
        if action_id == "governance_approve_action" or "approve" in (action_id or "").lower():
            action = DecisionAction.APPROVE
        elif action_id == "governance_reject_action" or "reject" in (action_id or "").lower() or "deny" in (action_id or "").lower():
            action = DecisionAction.REJECT
        else:
            raise CallbackRejected(f"Unrecognized governance action_id: '{action_id}'")

        return Decision(
            request_id=req_id,
            action=action,
            approver=approver,
            received_at=round(time.time(), 3),
            nonce=nonce,
        )

    def update(self, ref: MessageRef, outcome_text: str, final_status: str = "RESOLVED") -> None:
        """Replaces interactive buttons with final governance outcome card."""
        if not self.client or not ref.channel or not ref.message_ts:
            logger.info("[Slack Update] Mocked update for %s: %s", ref, outcome_text)
            return

        status_emoji = "✅" if "APPROV" in final_status.upper() else ("❌" if "REJECT" in final_status.upper() else "⏳")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{status_emoji} *GOVERNANCE DECISION: {final_status.upper()}*\n{outcome_text}\n_Updated at {now_str}_",
                },
            }
        ]

        try:
            self.client.chat_update(
                channel=ref.channel,
                ts=ref.message_ts,
                text=f"Decision: {final_status} — {outcome_text}",
                blocks=blocks,
            )
        except Exception as e:
            logger.error("[Slack Update] Failed to update message %s: %s", ref.message_ts, e)
