"""VIGIL Dynamic Real-Time Traffic Simulator.

Generates continuous background streams of mixed normal traffic and security threats
to feed the hybrid behavioral monitors, policy gates, and real-time visualization dashboards.
"""

import asyncio
import logging
import random
import time
from typing import Any, List

from ..runtime.models import AgentEvent, EventType, AgentStatus, WSEvent, WSEventType
from ..runtime.registry import AgentRegistry
from ..telemetry.monitor import BehavioralMonitor
from .threat_sim import ATTACK_SCENARIOS

logger = logging.getLogger("vigil.simulator")

NORMAL_TEMPLATES = {
    "customer_bot": [
        {
            "event_type": EventType.QUERY,
            "target": "user_input",
            "payload": "Hello, how do I reset my password?",
            "payload_size": 35,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "search_knowledge_base",
            "payload": "search password_reset_policy",
            "payload_size": 28,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "send_email",
            "payload": "recipient=user@example.com subject=Password Reset Link",
            "payload_size": 65,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "create_ticket",
            "payload": "priority=medium subject=Account access issue user_id=88392",
            "payload_size": 58,
        },
        {
            "event_type": EventType.AGENT_DELEGATION,
            "target": "analytics_agent",
            "payload": "Fetch monthly active history for user_88392",
            "payload_size": 44,
        },
        {
            "event_type": EventType.QUERY,
            "target": "user_input",
            "payload": "What is the status of my recent order #44219?",
            "payload_size": 46,
        },
        {
            "event_type": EventType.QUERY,
            "target": "user_input",
            "payload": "Can you help me update my billing address?",
            "payload_size": 42,
        },
    ],
    "analytics_agent": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "query_database",
            "payload": "SELECT user_cohort, COUNT(*) FROM users GROUP BY user_cohort",
            "payload_size": 68,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "generate_report",
            "payload": "generate_cohort_analytics_q2_pdf",
            "payload_size": 32,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "read_analytics",
            "payload": "fetch_dashboard_metrics period=last_7_days",
            "payload_size": 42,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "query_database",
            "payload": "SELECT COUNT(*) FROM sessions WHERE date > '2026-05-01'",
            "payload_size": 56,
        },
    ],
    "billing_agent": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "read_invoices",
            "payload": "SELECT * FROM invoices WHERE invoice_id = 99823",
            "payload_size": 55,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "process_refund",
            "payload": "refund amount=50.00 currency=USD order_id=44219",
            "payload_size": 52,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "send_receipt",
            "payload": "email=user@example.com invoice_id=99823 format=pdf",
            "payload_size": 60,
        },
    ],
    "support_agent": [
        {
            "event_type": EventType.QUERY,
            "target": "user_input",
            "payload": "Where is my parcel? Order ID: 44219",
            "payload_size": 35,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "retrieve_customer_details",
            "payload": "customer_id=77621",
            "payload_size": 17,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "update_order_status",
            "payload": "order_id=44219 status=IN_TRANSIT",
            "payload_size": 34,
        },
        {
            "event_type": EventType.AGENT_DELEGATION,
            "target": "billing_agent",
            "payload": "Verify payment status for transaction_883291",
            "payload_size": 47,
        },
    ],
    "hr_agent": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "fetch_employee_records",
            "payload": "employee_id=99281",
            "payload_size": 17,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "process_payroll",
            "payload": "month=May year=2026 status=APPROVED",
            "payload_size": 35,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "update_benefits",
            "payload": "employee_id=99281 plan=gold",
            "payload_size": 28,
        },
    ],
    "devops_bot": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "deploy_service",
            "payload": "service=auth_service tag=v2.1.0-release",
            "payload_size": 42,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "check_logs",
            "payload": "service=gateway lines=100 severity=ERROR",
            "payload_size": 38,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "restart_server",
            "payload": "node_id=us-east-1a-prod-02",
            "payload_size": 27,
        },
    ],
    "marketing_bot": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "send_campaign",
            "payload": "campaign_id=summer_sale segment=new_customers",
            "payload_size": 48,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "analyze_engagement",
            "payload": "campaign_id=summer_sale metric=click_rate",
            "payload_size": 45,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "update_segment",
            "payload": "segment_id=123 criteria=purchased_in_30_days",
            "payload_size": 50,
        },
        {
            "event_type": EventType.AGENT_DELEGATION,
            "target": "analytics_agent",
            "payload": "Fetch engagement metrics for summer sale campaign",
            "payload_size": 52,
        },
    ],
    "security_agent": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "scan_vulnerabilities",
            "payload": "target=api_gateway severity=high",
            "payload_size": 39,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "review_access",
            "payload": "user_id=54321 resource=customer_database",
            "payload_size": 53,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "update_policy",
            "payload": "policy_id=88 rule=password_expiry_days value=90",
            "payload_size": 57,
        },
        {
            "event_type": EventType.AGENT_DELEGATION,
            "target": "devops_bot",
            "payload": "Restart vulnerable service after patch",
            "payload_size": 41,
        },
    ],
    "compliance_bot": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "audit_logs",
            "payload": "period=last_30_days agent=customer_bot",
            "payload_size": 44,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "generate_report",
            "payload": "report_type=gdpr_compliance quarter=q2",
            "payload_size": 48,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "verify_access",
            "payload": "user_id=98765 permission=read_pii",
            "payload_size": 43,
        },
        {
            "event_type": EventType.AGENT_DELEGATION,
            "target": "security_agent",
            "payload": "Review access controls for compliance audit",
            "payload_size": 51,
        },
    ],
    "sales_agent": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "create_quote",
            "payload": "customer_id=11223 product=enterprise_plan amount=999",
            "payload_size": 58,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "update_crm",
            "payload": "lead_id=44556 status=qualified",
            "payload_size": 36,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "schedule_meeting",
            "payload": "contact=jane@company.com time=tomorrow_10am",
            "payload_size": 51,
        },
        {
            "event_type": EventType.AGENT_DELEGATION,
            "target": "billing_agent",
            "payload": "Process payment for new customer",
            "payload_size": 35,
        },
        {
            "event_type": EventType.AGENT_DELEGATION,
            "target": "marketing_bot",
            "payload": "Add new lead to nurture campaign",
            "payload_size": 38,
        },
    ],
    "research_agent": [
        {
            "event_type": EventType.TOOL_CALL,
            "target": "search_papers",
            "payload": "topic=machine_learning year=2026",
            "payload_size": 43,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "run_simulation",
            "payload": "model=neural_network epochs=100",
            "payload_size": 41,
        },
        {
            "event_type": EventType.TOOL_CALL,
            "target": "generate_summary",
            "payload": "paper_id=arxiv_2601.12345 length=500",
            "payload_size": 47,
        },
        {
            "event_type": EventType.AGENT_DELEGATION,
            "target": "analytics_agent",
            "payload": "Analyze simulation results",
            "payload_size": 30,
        },
    ],
}


class DynamicTrafficSimulator:
    """Simulates real-time, continuous background agent activity feeds."""

    def __init__(
        self,
        registry: AgentRegistry,
        monitor: BehavioralMonitor,
        event_bus: asyncio.Queue,
        interval_seconds: float = 1.0,
        attack_probability: float = 0.60,
        quarantine_duration_seconds: float = 20.0,
    ):
        """Initializes the background traffic simulator.

        Args:
            registry: The SQLite agent registry layer.
            monitor: The core pipeline behavioral monitor.
            event_bus: The global FastAPI WebSocket event bus.
            interval_seconds: Time delay between telemetry events.
            attack_probability: Chance of a threat event occurring (0.0 to 1.0).
            quarantine_duration_seconds: Time before an agent is auto-restored.
        """
        self.registry = registry
        self.monitor = monitor
        self.event_bus = event_bus
        self.interval = interval_seconds
        self.attack_prob = attack_probability
        self.quarantine_duration = quarantine_duration_seconds
        self.running = False
        
        # Track when agents were quarantined to handle automatic recoveries
        # quarantined_agents[agent_id] = epoch_timestamp
        self.quarantined_agents = {}

    async def start(self) -> None:
        """Starts the background continuous simulation loop."""
        if self.running:
            return
        
        self.running = True
        logger.info("Starting VIGIL Dynamic Real-Time Traffic Simulator...")
        asyncio.create_task(self._simulation_loop())
        asyncio.create_task(self._recovery_loop())

    async def stop(self) -> None:
        """Stops the background simulation loops."""
        self.running = False
        logger.info("Stopping VIGIL Dynamic Real-Time Traffic Simulator.")

    async def _simulation_loop(self) -> None:
        """Continuously feeds a mix of normal and attack telemetry to the monitor."""
        await asyncio.sleep(2.0)  # Brief warm-up sleep
        
        while self.running:
            try:
                # 1. Check which agents are currently quarantined
                agents_list = await self.registry.list_agents()
                active_agent_ids = [a.agent_id for a in agents_list if a.status == AgentStatus.NORMAL]
                
                if not active_agent_ids:
                    # If all agents are quarantined, sleep and wait for recovery loop to un-quarantine them
                    await asyncio.sleep(self.interval)
                    continue

                # Pick a random active agent to generate telemetry for
                agent_id = random.choice(active_agent_ids)

                # 2. Decide if this telemetry event is a normal event or an attack
                is_attack = random.random() < self.attack_prob
                
                if is_attack:
                    # Trigger an attack simulation
                    attack_type = random.choice(list(ATTACK_SCENARIOS.keys()))
                    scenario = ATTACK_SCENARIOS[attack_type]
                    
                    # Ensure we target the appropriate agent
                    target_agent = scenario["agent_id"]
                    
                    # If the targeted agent is quarantined, skip or target a normal agent instead
                    target_profile = await self.registry.get_agent(target_agent)
                    if target_profile and target_profile.status == AgentStatus.NORMAL:
                        event = AgentEvent(
                            agent_id=scenario["agent_id"],
                            event_type=scenario["event_type"],
                            target=scenario["target"],
                            payload=scenario["payload"],
                            payload_size=scenario["payload_size"],
                            timestamp=time.time(),
                        )
                        logger.info(f"[Simulator] Injection: Firing threat '{attack_type}' on '{scenario['agent_id']}'")
                        asyncio.create_task(self.monitor.observe(event))
                    else:
                        # Fallback to normal event if target agent is quarantined
                        await self._fire_normal_event(agent_id)
                else:
                    # Trigger normal telemetry
                    await self._fire_normal_event(agent_id)

            except Exception as e:
                logger.error(f"[Simulator] Error in simulation loop: {e}", exc_info=True)

            await asyncio.sleep(self.interval)

    async def _fire_normal_event(self, agent_id: str) -> None:
        """Pulls a random normal template for an agent and submits it to the pipeline."""
        templates = NORMAL_TEMPLATES.get(agent_id)
        if not templates:
            return

        tmpl = random.choice(templates)
        
        # Add slight variation to payload size and timestamp
        size_variation = random.randint(-5, 15)
        payload_size = max(5, tmpl["payload_size"] + size_variation)

        event = AgentEvent(
            agent_id=agent_id,
            event_type=tmpl["event_type"],
            target=tmpl["target"],
            payload=tmpl["payload"],
            payload_size=payload_size,
            timestamp=time.time(),
        )
        logger.info(f"[Simulator] Normal: Sending telemetry event for '{agent_id}' ({tmpl['event_type'].value})")
        asyncio.create_task(self.monitor.observe(event))

    async def _recovery_loop(self) -> None:
        """Periodically checks quarantined agents and restores them to NORMAL status."""
        while self.running:
            try:
                agents_list = await self.registry.list_agents()
                quarantined = [a for a in agents_list if a.status == AgentStatus.QUARANTINED]
                
                now = time.time()
                for agent in quarantined:
                    agent_id = agent.agent_id
                    
                    # If this is the first time we see this quarantined agent, track its quarantine timestamp
                    if agent_id not in self.quarantined_agents:
                        self.quarantined_agents[agent_id] = now
                        logger.info(f"[Simulator Recovery] Tracked quarantine timestamp for '{agent_id}'")
                        continue
                    
                    # Check if quarantine duration has passed
                    elapsed = now - self.quarantined_agents[agent_id]
                    if elapsed >= self.quarantine_duration:
                        # Restore agent back to normal!
                        logger.warning(f"[Simulator Recovery] Quarantine period expired for '{agent_id}'. Restoring to NORMAL status.")
                        await self.registry.update_status(agent_id, AgentStatus.NORMAL)
                        
                        # Fetch updated profile
                        profile = await self.registry.get_agent(agent_id)
                        if profile:
                            # Broadcast status change to WebSocket dashboards
                            await self.event_bus.put(
                                WSEvent(
                                    type=WSEventType.AGENT_UPDATE,
                                    agent_id=agent_id,
                                    payload=profile.model_dump(mode="json"),
                                    timestamp=time.time(),
                                )
                            )
                        
                        # Remove from quarantined tracker
                        self.quarantined_agents.pop(agent_id, None)

            except Exception as e:
                logger.error(f"[Simulator Recovery] Error in recovery loop: {e}", exc_info=True)

            await asyncio.sleep(2.0)
