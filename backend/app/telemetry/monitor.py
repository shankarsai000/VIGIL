"""VIGIL Behavioral Monitor.

Interceptors behavioral events from AI agents in real-time. Maintains sliding windows
of metric histories, computes statistical signals (call rates, payload distributions,
delegation volumes, and tool diversity), updates EWMA models, and pushes events through
the detection and remediation executors.
"""

from collections import deque
import logging
import time
from typing import Dict, Any, List, Optional

from ..runtime.models import AgentEvent, AgentProfile, ObservationResult, DetectionResult
from ..runtime.registry import AgentRegistry
from ..detection.detector import HybridDetector
from ..remediation.remediation import RemediationExecutor

logger = logging.getLogger("vigil.monitor")


class BehavioralMonitor:
    """Sliding-window behavioral logger and pipeline dispatcher for agent activities."""

    def __init__(
        self,
        registry: AgentRegistry,
        detector: HybridDetector,
        executor: RemediationExecutor,
        event_bus: Any,
        prompt_mutation_service=None,
        capability_enforcer_service=None,
        behavioral_spoofing_service=None,
    ):
        """Initializes the behavioral monitor.

        Args:
            registry: Database registry layer.
            detector: Hybrid security scanner.
            executor: Policy remediation executor.
            event_bus: Global system event queue.
            prompt_mutation_service: Optional VIGIL 2.0 prompt mutation detection service.
            capability_enforcer_service: Optional VIGIL 2.0 capability enforcement service.
            behavioral_spoofing_service: Optional VIGIL 2.0 behavioral spoofing detection service.
        """
        self.registry = registry
        self.detector = detector
        self.executor = executor
        self.event_bus = event_bus
        
        # VIGIL 2.0 detection services (optional)
        self.prompt_mutation_service = prompt_mutation_service
        self.capability_enforcer_service = capability_enforcer_service
        self.behavioral_spoofing_service = behavioral_spoofing_service
        
        # Sliding windows: windows[agent_id] = deque(AgentEvent, maxlen=500)
        self.windows: Dict[str, deque] = {}

    async def observe(self, event: AgentEvent) -> ObservationResult:
        """Processes an incoming event through the active pipeline.

        Applies sliding windows, updates baseline stats, feeds detection layers,
        and invokes remediation executors on anomalous scores.

        Args:
            event: The incoming AgentEvent.

        Returns:
            ObservationResult summary of detection & response actions.
        """
        agent_id = event.agent_id
        
        # 1. Fetch agent profile from DB
        profile = await self.registry.get_agent(agent_id)
        if not profile:
            logger.warning(f"[Monitor] Observed event for unregistered agent ID: '{agent_id}'. Discarding.")
            return ObservationResult(event=event, detection_result=None, action_taken=None)

        # 2. Append event to agent sliding window
        if agent_id not in self.windows:
            self.windows[agent_id] = deque(maxlen=500)
        self.windows[agent_id].append(event)

        # 3. Compute window statistics
        window = self.windows[agent_id]
        now = time.time()
        
        # Events in the last 60 seconds (for call rate calls/min)
        events_last_60s = [e for e in window if now - e.timestamp <= 60.0]
        call_rate = float(len(events_last_60s))

        # Average payload size
        payloads = [float(e.payload_size) for e in window]
        avg_payload_size = sum(payloads) / len(payloads) if payloads else 0.0

        # Delegation count in window
        delegation_count = sum(1 for e in window if e.event_type.value == "AGENT_DELEGATION")

        # Tool diversity in last 60 events
        last_60_events = list(window)[-60:]
        tool_targets = {e.target for e in last_60_events if e.event_type.value == "TOOL_CALL"}
        tool_diversity = float(len(tool_targets))

        window_stats = {
            "call_rate": call_rate,
            "avg_payload_size": avg_payload_size,
            "delegation_count": delegation_count,
            "tool_diversity": tool_diversity,
        }

        # 4. Feed baseline values back to EWMA tracker
        self.detector.ewma.update(agent_id, "call_rate", call_rate)
        self.detector.ewma.update(agent_id, "avg_payload_size", avg_payload_size)
        self.detector.ewma.update(agent_id, "delegation_count", float(delegation_count))
        self.detector.ewma.increment_count(agent_id)

        # 4b. VIGIL 2.0 — Run new detection layers and collect signals
        v2_signals: Dict[str, float] = {}
        
        # Prompt Mutation Detection
        if self.prompt_mutation_service and event.event_type.value == "QUERY":
            try:
                is_mutation, sim_score, lev_dist = await self.prompt_mutation_service.detect_mutation(
                    agent_id=agent_id,
                    incoming_prompt=event.payload
                )
                # Convert mutation detection to a threat score (1.0 - similarity = drift)
                v2_signals["prompt_mutation_score"] = (1.0 - sim_score) if is_mutation else 0.0
            except Exception as e:
                logger.error(f"[Monitor] Prompt mutation check failed for {agent_id}: {e}")

        # Capability Enforcement
        if self.capability_enforcer_service:
            try:
                action_type = "TOOL" if event.event_type.value in ("TOOL_CALL", "DATA_ACCESS") else "DESTINATION"
                is_violation, violation = await self.capability_enforcer_service.enforce_capabilities(
                    agent_id=agent_id,
                    action_type=action_type,
                    target=event.target
                )
                v2_signals["capability_score"] = 1.0 if is_violation else 0.0
            except Exception as e:
                logger.error(f"[Monitor] Capability enforcement check failed for {agent_id}: {e}")

        # Behavioral Spoofing Detection (run periodically, not every event)
        if self.behavioral_spoofing_service and len(self.windows.get(agent_id, [])) % 10 == 0:
            try:
                footprint = await self.behavioral_spoofing_service.analyze_behavioral_footprint(agent_id)
                v2_signals["spoofing_score"] = footprint.spoofing_likelihood
            except Exception as e:
                logger.error(f"[Monitor] Behavioral spoofing check failed for {agent_id}: {e}")

        # 5. Execute hybrid threat detection evaluation (with v2 signals)
        detection_result = await self.detector.detect(event, profile, window_stats, v2_signals=v2_signals)

        # 6. Database log the event along with score
        await self.registry.log_event(event, score=detection_result.score)

        # 7. Act on threats above baseline threshold (0.45)
        action_taken = None
        if detection_result.score >= 0.45:
            logger.warning(
                f"[Monitor] High threat threshold breached ({detection_result.score:.2f} >= 0.45) "
                f"for agent '{agent_id}'. Engaging Remediation..."
            )
            remediation_result = await self.executor.respond(event, detection_result, profile)
            action_taken = remediation_result.action_taken

        return ObservationResult(
            event=event,
            detection_result=detection_result,
            action_taken=action_taken,
        )

