"""VIGIL Policy Remediation Engine.

Defines and executes policy-authorized remediation actions (QUARANTINE, ALERT, LOG)
based on ArmorIQ Policy Decisions. Orchestrates the flow of agent confinement,
database logging, WebSocket alert dispatch, and plain-English explanations.
"""

import asyncio
import logging
import time
from uuid import uuid4
from typing import Dict, Any

from .models import (
    AgentEvent,
    AgentProfile,
    AgentStatus,
    DetectionResult,
    IncidentRecord,
    PolicyDecision,
    RemediationResult,
    ThreatContext,
    WSEvent,
    WSEventType,
)
from .registry import AgentRegistry
from .armoriq_gate import ArmorIQGate
from .explainer import VIGILExplainer

logger = logging.getLogger("vigil.remediation")


class RemediationExecutor:
    """Executes defensive and containment actions on agents based on ArmorIQ policy authorization."""

    def __init__(
        self,
        registry: AgentRegistry,
        gate: ArmorIQGate,
        event_bus: asyncio.Queue,
        explainer: VIGILExplainer,
    ):
        """Initializes the remediation executor.

        Args:
            registry: The database registry context.
            gate: The ArmorIQ Policy Gate.
            event_bus: The global FastAPI async Event Bus.
            explainer: The LLM plain-English explainer unit.
        """
        self.registry = registry
        self.gate = gate
        self.event_bus = event_bus
        self.explainer = explainer

    async def respond(
        self,
        event: AgentEvent,
        detection_result: DetectionResult,
        profile: AgentProfile,
    ) -> RemediationResult:
        """Evaluates a threat event, requests policy approval, and executes remediation.

        Args:
            event: The AgentEvent which triggered the alert.
            detection_result: The scores and details from the detection engine.
            profile: The profile of the subject agent.

        Returns:
            RemediationResult of the response transaction.
        """
        score = detection_result.score
        
        # 1. Determine Proposed Action based on Threat Score
        # - score >= 0.85 -> QUARANTINE (Immediate quarantine recommended)
        # - score >= 0.65 -> ALERT (Alert sent to security operations)
        # - else -> LOG (Audit trails logged only)
        if score >= 0.85:
            proposed_action = "QUARANTINE"
        elif score >= 0.65:
            proposed_action = "ALERT"
        else:
            proposed_action = "LOG"

        # 2. Build ThreatContext
        evidence = {
            "rule_score": detection_result.rule_score,
            "ewma_score": detection_result.ewma_score,
            "iforest_score": detection_result.iforest_score,
            "confidence": detection_result.confidence.value,
            "details": detection_result.details,
            "event": {
                "event_type": event.event_type.value,
                "target": event.target,
                "payload_size": event.payload_size,
            }
        }
        
        ctx = ThreatContext(
            agent_id=event.agent_id,
            threat_type=detection_result.threat_type,
            score=score,
            proposed_action=proposed_action,
            evidence=evidence,
            timestamp=time.time(),
        )

        # 3. Evaluate Policy Decision at ArmorIQ Gate
        policy_decision = await self.gate.evaluate_policy(ctx)
        logger.info(f"[Remediation] ArmorIQ returned policy decision {policy_decision.value} for {event.agent_id}")

        # 4. Resolve Action based on Policy Decision
        # - APPROVED -> Run the proposed action.
        # - ESCALATE -> Escalate action: replace LOG/QUARANTINE with ALERT to engage human oversight.
        # - DENIED -> Reject proposed containment, bypass execution (downgrade to LOG).
        final_action = "LOG"
        
        if policy_decision == PolicyDecision.APPROVED:
            final_action = proposed_action
        elif policy_decision == PolicyDecision.ESCALATE:
            logger.warning(f"[Remediation] Policy ESCALATION for {event.agent_id}. Overriding action '{proposed_action}' -> 'ALERT'")
            final_action = "ALERT"
        elif policy_decision == PolicyDecision.DENIED:
            logger.warning(f"[Remediation] Policy DENIED for {event.agent_id}. Discarding containment action '{proposed_action}' -> 'LOG'")
            final_action = "LOG"

        # 5. Create Incident Record
        incident_id = str(uuid4())
        incident = IncidentRecord(
            incident_id=incident_id,
            agent_id=event.agent_id,
            threat_type=detection_result.threat_type,
            detection_result=detection_result,
            policy_decision=policy_decision,
            action_taken=final_action,
            explanation="Generating explanation...",
            timestamp=time.time(),
            event=event,
        )

        # 6. Execute Container Operations
        if final_action == "QUARANTINE":
            await self._execute_quarantine(event.agent_id, incident)
        elif final_action == "ALERT":
            await self._execute_alert(incident)
        elif final_action == "LOG":
            await self._execute_log(incident)

        # 7. Audit Logging
        # Dispatched in background, does not block execution response
        await self.gate.log_audit(ctx, policy_decision, final_action)

        # 8. Fire-and-forget: Generate Plain English Explanation
        asyncio.create_task(self._process_explanation(incident))

        # 9. Assemble and return Remediation Result
        result = RemediationResult(
            agent_id=event.agent_id,
            action_taken=final_action,
            policy_decision=policy_decision,
            threat_type=detection_result.threat_type,
            score=score,
            timestamp=time.time(),
            incident_id=incident_id,
        )

        return result

    async def _execute_quarantine(self, agent_id: str, incident: IncidentRecord) -> None:
        """Concludes agent containment, flags state, and broadcasts updates."""
        logger.warning(f"[Remediation] EXECUTING QUARANTINE for agent: {agent_id}!")
        
        # Update registry status
        await self.registry.update_status(agent_id, AgentStatus.QUARANTINED)
        
        # Get updated profile
        profile = await self.registry.get_agent(agent_id)
        if profile:
            # Broadcast state change to all dashboards
            await self.event_bus.put(
                WSEvent(
                    type=WSEventType.AGENT_UPDATE,
                    agent_id=agent_id,
                    payload=profile.model_dump(mode="json"),
                    timestamp=time.time(),
                )
            )

        # Log incident & broadcast threat
        await self.registry.log_incident(incident)
        await self.event_bus.put(
            WSEvent(
                type=WSEventType.INCIDENT_DETECTED,
                agent_id=agent_id,
                payload=incident.model_dump(),
                timestamp=time.time(),
            )
        )

    async def _execute_alert(self, incident: IncidentRecord) -> None:
        """Broadcasting alert notification without confinement."""
        logger.warning(f"[Remediation] EXECUTING ALERT for agent: {incident.agent_id}!")
        
        # Log incident & broadcast threat feed alert
        await self.registry.log_incident(incident)
        await self.event_bus.put(
            WSEvent(
                type=WSEventType.INCIDENT_DETECTED,
                agent_id=incident.agent_id,
                payload=incident.model_dump(),
                timestamp=time.time(),
            )
        )

    async def _execute_log(self, incident: IncidentRecord) -> None:
        """Auditing security threat to the database without alerting the visual feed."""
        logger.info(f"[Remediation] EXECUTING LOG for agent: {incident.agent_id}. Incident silently audited.")
        # Just write to database
        await self.registry.log_incident(incident)

    async def _process_explanation(self, incident: IncidentRecord) -> None:
        """Calls the explainer module and publishes the explanation back to the feed."""
        try:
            explanation = await self.explainer.generate(incident)
            
            # Update SQLite incident table
            await self.registry.update_incident_explanation(incident.incident_id, explanation)
            
            # Broadcast update back to dashboards
            await self.event_bus.put(
                WSEvent(
                    type=WSEventType.EXPLANATION_READY,
                    agent_id=incident.agent_id,
                    payload={
                        "incident_id": incident.incident_id,
                        "explanation": explanation,
                    },
                    timestamp=time.time(),
                )
            )
        except Exception as e:
            logger.error(f"[Remediation] Explanation processor crashed: {e}", exc_info=True)
