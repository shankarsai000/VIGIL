"""VIGIL Seeding Module.

Defines and loads default demo agents (CustomerBot, AnalyticsAgent, BillingAgent)
into the database registry on system startup. Seeds the event history database
with baseline events to warm up statistical and machine learning layers.
"""

import asyncio
import logging
import random
import time
from datetime import datetime, timedelta

from .models import AgentProfile, AgentEvent, EventType, AgentStatus
from .registry import AgentRegistry

logger = logging.getLogger("vigil.seed")

# Predefined Demo Agent Profiles
DEMO_AGENTS = [
    AgentProfile(
        agent_id="customer_bot",
        name="CustomerBot",
        permitted_tools=["search_knowledge_base", "send_email", "create_ticket"],
        permitted_agents=["analytics_agent"],
        baseline_call_rate=8.0,
        status=AgentStatus.NORMAL,
        registered_at=datetime.utcnow(),
    ),
    AgentProfile(
        agent_id="analytics_agent",
        name="AnalyticsAgent",
        permitted_tools=["read_analytics", "generate_report", "query_database"],
        permitted_agents=[],
        baseline_call_rate=3.0,
        status=AgentStatus.NORMAL,
        registered_at=datetime.utcnow(),
    ),
    AgentProfile(
        agent_id="billing_agent",
        name="BillingAgent",
        permitted_tools=["read_invoices", "process_refund", "send_receipt"],
        permitted_agents=[],
        baseline_call_rate=2.0,
        status=AgentStatus.NORMAL,
        registered_at=datetime.utcnow(),
    ),
]


async def seed_agents(registry: AgentRegistry) -> None:
    """Populates the database with default agent profiles.

    Args:
        registry: The agent registry database module.
    """
    logger.info("Seeding demo agent profiles...")
    for agent in DEMO_AGENTS:
        # Check if already registered
        existing = await registry.get_agent(agent.agent_id)
        if not existing:
            await registry.register_agent(agent)
            logger.info(f"Seeded agent profile: {agent.name} ({agent.agent_id})")
        else:
            logger.info(f"Agent profile already registered: {agent.name}. Skipping registration seed.")


async def seed_baseline_events(registry: AgentRegistry, monitor: Any) -> None:
    """Injects historical events to warm up the statistical baseline EWMA models.

    Fires 20 normal events per agent spread over the last 10 minutes. Updates EWMA baselines
    and increments counts directly without triggering active remediation alerts.

    Args:
        registry: Database registry layer.
        monitor: BehavioralMonitor instance to receive baseline inputs.
    """
    logger.info("Seeding telemetry baseline records to warm up EWMA models...")
    
    now = time.time()
    
    for agent in DEMO_AGENTS:
        # Check existing event volume
        count = await registry.get_event_count(agent.agent_id)
        if count >= 20:
            logger.info(f"Agent {agent.name} already has {count} telemetry logs. Skipping baseline seed.")
            
            # Rehydrate EWMA model for this running session
            logger.info(f"Hydrating active EWMA tracking models for {agent.name} from database...")
            events = await registry.get_events(agent.agent_id, limit=100)
            
            # Feed to EWMA in reverse order (oldest to newest)
            events.reverse()
            for ev in events:
                # Approximate call rate windowing
                # Since we don't have full window snapshots, we update based on baseline rates
                monitor.detector.ewma.update(agent.agent_id, "call_rate", agent.baseline_call_rate)
                monitor.detector.ewma.update(agent.agent_id, "avg_payload_size", ev["payload_size"])
                monitor.detector.ewma.update(agent.agent_id, "delegation_count", 0.0)
                monitor.detector.ewma.increment_count(agent.agent_id)
            continue

        logger.info(f"Generating 20 baseline events for {agent.name}...")
        
        # We fire 20 events spread out
        for i in range(20):
            # Select random permitted tool
            tool = random.choice(agent.permitted_tools)
            payload_size = random.randint(50, 500)
            
            # Spread timestamps over the last 10 minutes (600s)
            timestamp = now - random.uniform(50, 600)
            
            event = AgentEvent(
                agent_id=agent.agent_id,
                event_type=EventType.TOOL_CALL,
                target=tool,
                payload="normal_operation_payload",
                payload_size=payload_size,
                timestamp=timestamp,
            )
            
            # Log event to database with 0.0 threat score
            await registry.log_event(event, score=0.0)
            
            # Update active detector EWMA baseline directly
            # Use baseline parameters to warm up call rate model
            monitor.detector.ewma.update(agent.agent_id, "call_rate", agent.baseline_call_rate + random.uniform(-1, 1))
            monitor.detector.ewma.update(agent.agent_id, "avg_payload_size", float(payload_size))
            monitor.detector.ewma.update(agent.agent_id, "delegation_count", 0.0)
            monitor.detector.ewma.increment_count(agent.agent_id)
            
        logger.info(f"Baseline successfully seeded for {agent.name}.")
