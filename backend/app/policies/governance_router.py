import logging
import time
from typing import Tuple
from ..runtime.models import (
    ThreatContext,
    PolicyDecision,
    ThreatType,
    GovernanceVerdict,
    TelegramRole,
)
from .armoriq_gate import ArmorIQGate
from ..runtime.registry import AgentRegistry
from ..config import VigilSettings

logger = logging.getLogger("vigil.policies.governance_router")


class GovernanceRouter:
    """Central governance decision engine for VIGIL's governed runtime layer."""

    def __init__(self, gate: ArmorIQGate, registry: AgentRegistry, settings: VigilSettings):
        self.gate = gate
        self.registry = registry
        self.settings = settings

    async def evaluate_request(
        self,
        agent_id: str,
        prompt_analysis: dict,
        threat_score: float,
        user_role: TelegramRole,
    ) -> Tuple[GovernanceVerdict, PolicyDecision]:
        """Evaluates prompt analysis, threat score, and operator roles against policy."""
        # Determine proposed containment action
        if threat_score >= 0.85:
            proposed_action = "QUARANTINE"
        elif threat_score >= 0.65:
            proposed_action = "ALERT"
        else:
            proposed_action = "LOG"

        # Determine threat level category
        if threat_score >= 0.85:
            threat_level = "CRITICAL"
        elif threat_score >= 0.65:
            threat_level = "HIGH"
        elif threat_score >= 0.30:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        # Build context
        try:
            threat_type_enum = ThreatType(prompt_analysis.get("label", "BENIGN_OPERATION"))
        except ValueError:
            # Fallback in case of custom label or missing mapping
            threat_type_enum = ThreatType.BENIGN_OPERATION

        ctx = ThreatContext(
            agent_id=agent_id,
            threat_type=threat_type_enum,
            score=threat_score,
            proposed_action=proposed_action,
            evidence={
                "governance_category": prompt_analysis.get("governance_category", "PERMITTED"),
                "is_injection": prompt_analysis.get("is_injection", False),
                "confidence": prompt_analysis.get("confidence", 0.0),
                "user_role": user_role.value,
                "threat_level": threat_level,
            },
            timestamp=time.time(),
        )

        policy_decision = await self.gate.evaluate_policy(ctx)
        logger.info(
            f"[Governance Router] Evaluating request for agent {agent_id}: "
            f"Threat Level={threat_level}, Policy={policy_decision.value}, SleepMode={self.settings.telegram_sleep_mode}"
        )

        # Apply Decision Matrix
        if policy_decision == PolicyDecision.DENIED:
            return GovernanceVerdict.DENY, policy_decision

        if policy_decision == PolicyDecision.APPROVED:
            if threat_level in ["LOW", "MEDIUM"]:
                return GovernanceVerdict.ALLOW, policy_decision
            
            # HIGH or CRITICAL
            if self.settings.telegram_sleep_mode:
                logger.info(f"[Governance Router] Sleep Mode active: Auto-Approving {threat_level} threat.")
                # We also want to record this in the audit log that it was auto-approved
                await self.gate.log_audit(ctx, policy_decision, proposed_action)
                return GovernanceVerdict.ALLOW, policy_decision
            
            return GovernanceVerdict.REQUIRE_APPROVAL, policy_decision

        if policy_decision == PolicyDecision.ESCALATE:
            return GovernanceVerdict.REQUIRE_APPROVAL, policy_decision

        # Fallback to DENY for safety
        return GovernanceVerdict.DENY, policy_decision
