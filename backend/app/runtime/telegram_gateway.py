import logging
import time
from typing import Tuple, Dict, Any, Optional
from uuid import uuid4

from .models import (
    AgentEvent,
    AgentProfile,
    AgentStatus,
    EventType,
    IncidentRecord,
    PolicyDecision,
    WSEvent,
    WSEventType,
    GovernanceVerdict,
    TelegramUser,
    ApprovalRequest,
    ApprovalStatus,
    DetectionResult,
    Confidence,
    ThreatType,
)
from .registry import AgentRegistry
from ..policies.governance_router import GovernanceRouter
from ...services.armorclaw_service import armorclaw_service
from ...services.scoring_service import scoring_service
from ...services.notification_service import NotificationService
from ..remediation.remediation import RemediationExecutor

logger = logging.getLogger("vigil.runtime.telegram_gateway")


class TelegramGateway:
    """Governance gateway routing Telegram messages through ArmorClaw -> VIGIL -> ArmorIQ."""

    def __init__(
        self,
        registry: AgentRegistry,
        governance_router: GovernanceRouter,
        remediation: RemediationExecutor,
        notifications: NotificationService,
    ):
        self.registry = registry
        self.governance_router = governance_router
        self.remediation = remediation
        self.notifications = notifications
        self.detector = None

    async def process_message(
        self,
        agent_id: str,
        message_text: str,
        user: TelegramUser,
    ) -> Dict[str, Any]:
        """Entry point for all operator conversational prompts targeting runtime agents."""
        logger.info(f"[Telegram Gateway] Processing message from user {user.telegram_id} for agent {agent_id}: '{message_text}'")
        
        # 1. Verify agent existence & status
        profile = await self.registry.get_agent(agent_id)
        if not profile:
            return {
                "success": False,
                "verdict": GovernanceVerdict.DENY.value,
                "message": f"❌ Agent <code>{agent_id}</code> is not registered in the system.",
            }
            
        if profile.status == AgentStatus.QUARANTINED:
            return {
                "success": False,
                "verdict": GovernanceVerdict.DENY.value,
                "message": f"❌ Agent <code>{agent_id}</code> is currently QUARANTINED and cannot execute instructions.",
            }

        # 2. Run ArmorClaw Prompt Analysis
        analysis = await armorclaw_service.analyze_prompt(message_text)
        
        # 3. Formulate event for rules check
        event = AgentEvent(
            agent_id=agent_id,
            event_type=EventType.QUERY,
            target="telegram",
            payload=message_text,
            payload_size=len(message_text.encode("utf-8")),
        )
        
        rule_score = 0.0
        rule_threat = ThreatType.NONE
        if self.detector:
            rule_score, rule_threat = self.detector.rule_engine.evaluate(event, profile)
            
        # 4. Compute Threat Score
        threat_score = scoring_service.calculate_threat_score(
            rule_score=rule_score,
            ewma_score=0.0,
            iforest_score=0.0,
            armorclaw_score=analysis["confidence"]
        )
        
        # 5. Evaluate Governance Policy Decision
        verdict, policy_decision = await self.governance_router.evaluate_request(
            agent_id=agent_id,
            prompt_analysis=analysis,
            threat_score=threat_score,
            user_role=user.role,
        )
        
        logger.info(f"[Telegram Gateway] Verdict determined: {verdict.value} (Policy: {policy_decision.value})")

        # 6. Respond and execute based on verdict
        if verdict == GovernanceVerdict.ALLOW:
            return {
                "success": True,
                "verdict": verdict.value,
                "policy_decision": policy_decision.value,
                "threat_score": threat_score,
                "message": f"🛡 <b>VIGIL Governance: ALLOWED</b>\n"
                           f"• Agent: <code>{agent_id}</code>\n"
                           f"• Threat Score: <code>{threat_score:.2f}</code>\n"
                           f"• Action: <code>EXECUTE</code>\n\n"
                           f"✅ <b>Execution Result:</b>\n"
                           f"Command processed successfully by <code>{agent_id}</code> without exceptions.",
            }
            
        elif verdict == GovernanceVerdict.DENY:
            # Trigger remediation pipeline
            detection_result = DetectionResult(
                score=threat_score,
                threat_type=rule_threat if rule_score > 0.0 else ThreatType(analysis.get("label", "BENIGN_OPERATION")),
                confidence=Confidence.from_score(threat_score),
                rule_score=rule_score,
                ewma_score=0.0,
                iforest_score=0.0,
                details={
                    "telegram_user": user.telegram_id,
                    "armorclaw_label": analysis["label"],
                    "armorclaw_score": analysis["confidence"],
                }
            )
            
            remediation_result = await self.remediation.respond(event, detection_result, profile)
            
            msg = (
                f"🛡 <b>VIGIL Governance: DENIED</b>\n"
                f"• Agent: <code>{agent_id}</code>\n"
                f"• Threat Score: <code>{threat_score:.2f}</code>\n"
                f"• Remediation: <code>{remediation_result.action_taken}</code>\n\n"
                f"❌ <b>Execution Result:</b>\n"
                f"Request blocked. Threat detected by ArmorClaw/VIGIL and containment applied."
            )
            return {
                "success": False,
                "verdict": verdict.value,
                "policy_decision": policy_decision.value,
                "threat_score": threat_score,
                "message": msg,
            }
            
        elif verdict == GovernanceVerdict.REQUIRE_APPROVAL:
            proposed_action = "QUARANTINE" if threat_score >= 0.85 else "ALERT"
            approval_request = ApprovalRequest(
                incident_id=str(uuid4()),
                agent_id=agent_id,
                threat_type=rule_threat if rule_score > 0.0 else ThreatType(analysis.get("label", "BENIGN_OPERATION")),
                threat_score=threat_score,
                proposed_action=proposed_action,
                status=ApprovalStatus.PENDING,
            )
            
            # Log incident to display in history
            incident = IncidentRecord(
                incident_id=approval_request.incident_id,
                agent_id=agent_id,
                threat_type=approval_request.threat_type,
                detection_result=DetectionResult(
                    score=threat_score,
                    threat_type=approval_request.threat_type,
                    confidence=Confidence.from_score(threat_score),
                    rule_score=rule_score,
                    ewma_score=0.0,
                    iforest_score=0.0,
                    details={"source": "TelegramGateway", "needs_approval": True}
                ),
                policy_decision=policy_decision,
                action_taken="AWAITING_APPROVAL",
                explanation="Awaiting operator governance approval via Telegram card.",
                timestamp=time.time(),
                event=event,
            )
            await self.registry.log_incident(incident)
            
            # Broadcast incident pending approval to WebSocket
            await self.registry.event_bus.put(
                WSEvent(
                    type=WSEventType.INCIDENT_DETECTED,
                    agent_id=agent_id,
                    payload=incident.model_dump(),
                    timestamp=time.time(),
                )
            )
            
            # Dispatch approval card
            await self.notifications.send_approval_card(approval_request)
            
            msg = (
                f"🛡 <b>VIGIL Governance: AWAITING APPROVAL</b>\n"
                f"• Agent: <code>{agent_id}</code>\n"
                f"• Threat Score: <code>{threat_score:.2f}</code>\n"
                f"• Verdict: <code>PENDING OPERATOR DECISION</code>\n\n"
                f"🚨 Your request has been flagged. A governance card has been dispatched to Security Operations."
            )
            return {
                "success": False,
                "verdict": verdict.value,
                "policy_decision": policy_decision.value,
                "threat_score": threat_score,
                "message": msg,
            }
            
        return {
            "success": False,
            "verdict": GovernanceVerdict.DENY.value,
            "message": "❌ Unknown governance verdict.",
        }
