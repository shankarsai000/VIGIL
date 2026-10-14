import logging
import time
from typing import Dict

logger = logging.getLogger("vigil.services.quarantine")

class QuarantineService:
    """Manages active isolations, automated cooldown lifespans, and manual operator overrides."""

    def __init__(self, default_duration_seconds: float = 20.0):
        self.default_duration = default_duration_seconds
        # Structure: quarantined_agents[agent_id] = quarantine_start_timestamp
        self.quarantined_agents: Dict[str, float] = {}

    def isolate_agent(self, agent_id: str, duration: float = None) -> None:
        """Puts a specific agent under secure isolation containment."""
        start_time = time.time()
        self.quarantined_agents[agent_id] = start_time
        logger.warning(f"[Quarantine Service] Agent isolated: '{agent_id}' starting now.")

    def release_agent(self, agent_id: str) -> None:
        """Manually lifts the quarantine isolation envelope for an agent."""
        self.quarantined_agents.pop(agent_id, None)
        logger.info(f"[Quarantine Service] Released agent: '{agent_id}' from containment.")

    def is_isolated(self, agent_id: str) -> bool:
        """Returns True if the agent is currently under quarantine isolation."""
        return agent_id in self.quarantined_agents

    def check_for_recovery(self, agent_id: str, duration_override: float = None) -> bool:
        """Determines if an agent's quarantine cooldown lifespan has completely elapsed."""
        if not self.is_isolated(agent_id):
            return False
            
        start_time = self.quarantined_agents[agent_id]
        duration = duration_override if duration_override is not None else self.default_duration
        
        elapsed = time.time() - start_time
        if elapsed >= duration:
            logger.warning(f"[Quarantine Service] Quarantine cooldown completely elapsed for '{agent_id}'.")
            return True
        return False

# Singleton service instance
quarantine_service = QuarantineService()
