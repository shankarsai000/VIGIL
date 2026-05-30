import logging
import time
from typing import Tuple, List, Optional
from ..app.runtime.models import CapabilityProfile, CapabilityViolation

logger = logging.getLogger("vigil.services.capability_enforcer")

class CapabilityEnforcerService:
    """Learns and enforces per-agent behavioral whitelists for tools and delegation targets."""
    
    def __init__(self, registry):
        self.registry = registry

    async def learn_agent_capabilities(self, agent_id: str) -> CapabilityProfile:
        """Analyzes historical telemetry to build/update tool/destination whitelists."""
        # Query historical events for this agent
        # We can fetch recent events from the registry
        # Let's see if registry has get_events or similar. If not, query events directly
        allowed_tools = set()
        allowed_destinations = set()
        
        # Access agent profile to pre-seed permitted items
        agent = await self.registry.get_agent(agent_id)
        if agent:
            allowed_tools.update(agent.permitted_tools)
            allowed_destinations.update(agent.permitted_agents)
            
        # Also analyze historical events for learned behaviors
        rows = await self.registry.db.fetch(
            "SELECT event_type, target FROM events WHERE agent_id = ?",
            (agent_id,),
        )
        for row in rows:
            ev_type, target = row["event_type"], row["target"]
            if ev_type == "TOOL_CALL":
                allowed_tools.add(target)
            elif ev_type == "AGENT_DELEGATION":
                allowed_destinations.add(target)
                        
        profile = CapabilityProfile(
            agent_id=agent_id,
            allowed_tools=list(allowed_tools),
            allowed_destinations=list(allowed_destinations),
            learned_at=time.time()
        )
        await self.registry.save_capability_profile(profile)
        logger.info(f"Learned capabilities profile for {agent_id}. Permitted tools: {profile.allowed_tools}, Permitted agents: {profile.allowed_destinations}")
        return profile

    async def enforce_capabilities(self, agent_id: str, action_type: str, target: str) -> Tuple[bool, Optional[CapabilityViolation]]:
        """Verifies if an action matches the agent's capability profile.
        
        action_type can be 'TOOL' or 'DESTINATION'.
        """
        profile = await self.registry.get_capability_profile(agent_id)
        if not profile:
            # First-time profile creation/learning
            profile = await self.learn_agent_capabilities(agent_id)

        is_violation = False
        violation = None

        if action_type == "TOOL":
            if target not in profile.allowed_tools:
                is_violation = True
        elif action_type == "DESTINATION":
            if target not in profile.allowed_destinations:
                is_violation = True

        if is_violation:
            violation = CapabilityViolation(
                agent_id=agent_id,
                action_type=action_type,
                target=target,
                timestamp=time.time()
            )
            await self.registry.log_capability_violation(violation)
            logger.warning(f"CAPABILITY VIOLATION: Agent {agent_id} tried to access {action_type} {target}")

        return is_violation, violation

