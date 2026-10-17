"""ArmorIQ policy gate for containment decisions (SDK-based; replaces the earlier custom HTTP gate).

Mode is set by ARMORIQ_MODE:

- live: containment is authorized by ArmorIQ. The gate captures a plan for quarantine_agent, mints an intent
  token with an inline policy, and performs a governed invoke on the containment MCP server, which carries out
  the quarantine. Requires a real ARMORIQ_API_KEY and ARMORIQ_USER_EMAIL.
- disabled (default): no containment can be authorized. Quarantine proposals are escalated to a human.
  Nothing is simulated.
- local-demo: deterministic thresholds for offline demos only. Every decision is labelled
  "NOT ArmorIQ" in the audit trail. Not valid for a submission.

Fail closed: an error, a timeout, a hold, an unexpected response, or a missing key never yields APPROVED for a
containment action. A hold becomes ESCALATE, and an explicit policy denial becomes DENIED.
Non-destructive proposals (ALERT, LOG) need no containment authority and are APPROVED without a network call.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, List, Optional

from armoriq_sdk import (
    ArmorIQClient,
    ArmorIQException,
    InvokeOptions,
    PolicyBlockedException,
    PolicyHoldException,
)

from ..runtime.ledger import AuditLedger
from ..runtime.models import AgentProfile, AuditEntry, PolicyDecision, ThreatContext

if TYPE_CHECKING:
    from ..runtime.registry import AgentRegistry

logger = logging.getLogger("vigil.armoriq_gate")

CONTAINMENT_TOOL = "quarantine_agent"
MODES = ("live", "disabled", "local-demo")
AUTHORIZATION_TIMEOUT_S = 20.0


def _local_demo_decision(score: float) -> PolicyDecision:
    # Uses centralized thresholds from config/thresholds.yaml
    from ..runtime.thresholds import SystemThresholds
    if score >= SystemThresholds.quarantine():
        return PolicyDecision.APPROVED
    if score >= SystemThresholds.escalate():
        return PolicyDecision.ESCALATE
    return PolicyDecision.APPROVED


class ArmorIQGate:
    """Containment gate. Keeps the interface the remediation executor and main.py already use."""

    def __init__(self, config: Any, registry: "AgentRegistry", ledger: Optional[AuditLedger] = None,
                 client_factory: Any = None) -> None:
        self.config = config
        self.registry = registry
        self.mode = str(config.armoriq_mode).strip().lower()
        if self.mode not in MODES:
            raise ValueError(f"ARMORIQ_MODE must be one of {MODES}, got {self.mode!r}")
        self.ledger = ledger or AuditLedger(config.audit_ledger_path)
        self._client_factory = client_factory
        self.client: Optional[ArmorIQClient] = None

    @property
    def enforced_by_armoriq(self) -> bool:
        return self.mode == "live"

    async def startup(self) -> None:
        if self.mode == "live":
            key = (self.config.armoriq_api_key or "").strip()
            if not key or key == "mock":
                raise RuntimeError("ARMORIQ_MODE=live needs a real ARMORIQ_API_KEY. Refusing to start.")
            if not self.config.armoriq_user_email:
                raise RuntimeError("ARMORIQ_MODE=live needs ARMORIQ_USER_EMAIL (the principal the SDK acts for).")
            if self._client_factory is not None:
                self.client = self._client_factory()
            else:
                self.client = ArmorIQClient(
                    api_key=key,
                    user_id=self.config.armoriq_user_email,
                    agent_id=self.config.armoriq_agent_id,
                    use_production=self.config.armoriq_use_production,
                )
            logger.info("ArmorIQ gate: LIVE. Containment is authorized by ArmorIQ.")
        elif self.mode == "disabled":
            logger.warning("ArmorIQ gate: DISABLED. Quarantine is escalated to a human; nothing is executed.")
        else:
            logger.warning("ArmorIQ gate: LOCAL-DEMO. Decisions are NOT enforced by ArmorIQ.")

    async def shutdown(self) -> None:
        self.client = None

    async def register_agent(self, profile: AgentProfile) -> str:
        # Agent identities are onboarded with the armoriq CLI (see config/). Nothing is registered at runtime.
        return f"local:{profile.agent_id}"

    async def evaluate_policy(self, ctx: ThreatContext) -> PolicyDecision:
        if ctx.proposed_action != "QUARANTINE":
            return PolicyDecision.APPROVED
        return await self.authorize_containment(ctx)

    async def authorize_containment(self, ctx: ThreatContext, human_approved: bool = False) -> PolicyDecision:
        """Decides whether a quarantine may run.

        A human approval unlocks containment in local-demo only. In live mode it changes nothing: an ArmorIQ hold
        stays ESCALATE and a denial stays DENIED. In disabled mode nothing is contained, approved or not.
        """
        if self.mode == "disabled":
            return PolicyDecision.ESCALATE
        if self.mode == "local-demo":
            return PolicyDecision.APPROVED if human_approved else _local_demo_decision(ctx.score)
        return await self._authorize_containment(ctx)

    async def _authorize_containment(self, ctx: ThreatContext) -> PolicyDecision:
        if self.client is None:
            logger.error("ArmorIQ client is not started; escalating instead of containing %s.", ctx.agent_id)
            return PolicyDecision.ESCALATE
        try:
            # The SDK calls block on the network. Run them in a worker thread so the event loop keeps serving.
            return await asyncio.wait_for(asyncio.to_thread(self._authorize_sync, ctx), AUTHORIZATION_TIMEOUT_S)
        except asyncio.TimeoutError:
            logger.error("ArmorIQ authorization timed out for %s; escalating.", ctx.agent_id)
            return PolicyDecision.ESCALATE

    def _authorize_sync(self, ctx: ThreatContext) -> PolicyDecision:
        mcp = self.config.armoriq_containment_mcp_id
        goal = f"Contain agent {ctx.agent_id} after {ctx.threat_type.value}"
        plan = {"goal": goal, "steps": [{"action": CONTAINMENT_TOOL, "mcp": mcp, "params": {}}]}
        params = {"agent_id": ctx.agent_id, "reason": ctx.threat_type.value, "score": round(float(ctx.score), 4)}
        try:
            captured = self.client.capture_plan(llm="vigil-policy-gate", prompt=goal, plan=plan)
            token = self.client.get_intent_token(
                captured,
                policy={"allow": [f"{mcp}/{CONTAINMENT_TOOL}"], "deny": []},
                validity_seconds=self.config.armoriq_token_validity_seconds,
            )
            result = self.client.invoke_with_policy(
                mcp,
                CONTAINMENT_TOOL,
                token,
                params,
                options=InvokeOptions(user_email=self.config.armoriq_user_email, wait_for_approval=False),
            )
        except PolicyHoldException:
            logger.warning("ArmorIQ held containment of %s for approval; escalating.", ctx.agent_id)
            return PolicyDecision.ESCALATE
        except PolicyBlockedException as exc:
            logger.warning("ArmorIQ denied containment of %s: %s", ctx.agent_id, exc)
            return PolicyDecision.DENIED
        except ArmorIQException as exc:
            logger.error("ArmorIQ error while authorizing containment of %s: %s; escalating.", ctx.agent_id, exc)
            return PolicyDecision.ESCALATE
        except Exception as exc:  # fail closed on anything unexpected
            logger.error("Unexpected error while authorizing containment of %s: %s; escalating.", ctx.agent_id, exc)
            return PolicyDecision.ESCALATE
        if getattr(result, "status", "error") != "success":
            logger.error("The containment tool reported an error for %s; escalating.", ctx.agent_id)
            return PolicyDecision.ESCALATE
        return PolicyDecision.APPROVED

    async def log_audit(self, ctx: ThreatContext, decision: PolicyDecision, action: str, source: Optional[str] = None) -> None:
        src = source or getattr(ctx, "source", None) or "gate"
        enforcement = "armoriq-live" if self.mode == "live" else f"{self.mode} (NOT ArmorIQ)"
        record = {
            "agent_id": ctx.agent_id,
            "threat_type": ctx.threat_type.value,
            "score": round(float(ctx.score), 4),
            "proposed_action": ctx.proposed_action,
            "decision": decision.value,
            "action": action,
            "enforcement": enforcement,
            "source": src,
        }
        try:
            self.ledger.append(record)
        except Exception as exc:
            logger.error("Failed to append to the audit ledger: %s", exc)
        entry = AuditEntry(
            agent_id=ctx.agent_id,
            decision=decision,
            action=action,
            score=ctx.score,
            threat_type=ctx.threat_type,
            timestamp=time.time(),
            source=f"vigil:{enforcement}",
        )
        try:
            await self.registry.log_policy_decision(entry)
        except Exception as exc:
            logger.error("Failed to write the audit entry to the registry: %s", exc)

    async def get_audit_log(self, limit: int = 50) -> List[AuditEntry]:
        return await self.registry.get_audit_log(limit)
