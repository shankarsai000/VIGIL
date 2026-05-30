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

from .models import AgentEvent, AgentProfile, ObservationResult, DetectionResult
from .registry import AgentRegistry
from .detector import HybridDetector
from .remediation import RemediationExecutor

logger = logging.getLogger("vigil.monitor")


class BehavioralMonitor:
    """Sliding-window behavioral logger and pipeline dispatcher for agent activities."""

    def __init__(
        self,
        registry: AgentRegistry,
        detector: HybridDetector,
        executor: RemediationExecutor,
        event_bus: Any,
    ):
        """Initializes the behavioral monitor.

        Args:
            registry: Database registry layer.
            detector: Hybrid security scanner.
            executor: Policy remediation executor.
            event_bus: Global system event queue.
        """
        self.registry = registry
        self.detector = detector
        self.executor = executor
        self.event_bus = event_bus
        
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

        # 5. Execute hybrid threat detection evaluation
        detection_result = await self.detector.detect(event, profile, window_stats)

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
