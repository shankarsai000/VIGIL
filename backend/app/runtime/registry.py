"""VIGIL agent registry database layer.

Manages data storage and retrieval using non-blocking asynchronous operations
over a local SQLite database via aiosqlite. Handles schemas for agents,
events, incidents, and audit entries.
"""

import json
import logging
import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any
import aiosqlite

from .models import (
    AgentProfile,
    AgentEvent,
    AgentStatus,
    EventType,
    IncidentRecord,
    AuditEntry,
    PolicyDecision,
    ThreatType,
    DetectionResult,
    Confidence,
    TelegramUser,
    TelegramRole,
    ApprovalRequest,
    ApprovalStatus,
    GovernanceAction,
    NotificationRecord,
    ModelIntegrityBaseline,
    ModelIntegrityEvent,
    CapabilityProfile,
    CapabilityViolation,
    SupplyChainDependency,
    SupplyChainEvent,
    PromptMutationRecord,
    AttackGraphNode,
    AttackGraphEdge,
    RemediationScript,
    TamperProofIncident,
    RemediationChain,
    BehavioralFootprintScore,
)

logger = logging.getLogger("vigil.registry")


class AgentRegistry:
    """Manages the lifecycle, events, incidents and audit history of VIGIL agents in SQLite."""

    def __init__(self, db_path: str):
        """Initializes the registry with a database path.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path

    async def init_db(self) -> None:
        """Initializes the database schema if tables do not exist."""
        logger.info("Initializing VIGIL SQLite database...")
        async with aiosqlite.connect(self.db_path) as db:
            # Enable WAL mode for performance
            await db.execute("PRAGMA journal_mode=WAL")
            
            # Agents Table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    permitted_tools TEXT NOT NULL, -- JSON List
                    permitted_agents TEXT NOT NULL, -- JSON List
                    baseline_call_rate REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'NORMAL',
                    registered_at TEXT NOT NULL,
                    armoriq_id TEXT
                )
            """)

            # Events Table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    payload_size INTEGER NOT NULL,
                    score REAL DEFAULT 0.0,
                    timestamp REAL NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)

            # Incidents Table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    score REAL NOT NULL,
                    action_taken TEXT NOT NULL,
                    policy_decision TEXT NOT NULL,
                    explanation TEXT NOT NULL DEFAULT '',
                    timestamp REAL NOT NULL,
                    detection_result TEXT NOT NULL, -- JSON representation of DetectionResult
                    event_data TEXT NOT NULL, -- JSON representation of AgentEvent
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                )
            """)

            # Audit Table (Policy Decisions)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS policy_decisions (
                    entry_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    action TEXT NOT NULL,
                    score REAL NOT NULL,
                    threat_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    source TEXT NOT NULL DEFAULT 'vigil'
                )
            """)

            # ━━━━ Telegram Governed Runtime Tables ━━━━

            # Telegram Users RBAC Table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS telegram_users (
                    telegram_id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL DEFAULT '',
                    display_name TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL DEFAULT 'OBSERVER',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    registered_at REAL NOT NULL,
                    last_seen REAL NOT NULL
                )
            """)

            # Approval Requests Queue
            await db.execute("""
                CREATE TABLE IF NOT EXISTS approval_requests (
                    request_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    threat_score REAL NOT NULL,
                    proposed_action TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    requested_at REAL NOT NULL,
                    resolved_at REAL,
                    resolved_by INTEGER,
                    telegram_message_id INTEGER,
                    chat_id INTEGER
                )
            """)

            # Governance Actions Audit Trail
            await db.execute("""
                CREATE TABLE IF NOT EXISTS governance_actions (
                    action_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    telegram_user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (request_id) REFERENCES approval_requests(request_id)
                )
            """)

            # Incident Notifications Tracking
            await db.execute("""
                CREATE TABLE IF NOT EXISTS incident_notifications (
                    notification_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL DEFAULT '',
                    chat_id INTEGER NOT NULL,
                    notification_type TEXT NOT NULL,
                    content_summary TEXT NOT NULL DEFAULT '',
                    sent_at REAL NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 1
                )
            """)

            # Telegram Sessions
            await db.execute("""
                CREATE TABLE IF NOT EXISTS telegram_sessions (
                    session_id TEXT PRIMARY KEY,
                    telegram_id INTEGER NOT NULL,
                    started_at REAL NOT NULL,
                    last_activity REAL NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY (telegram_id) REFERENCES telegram_users(telegram_id)
                )
            """)

            # Model Integrity Baselines
            await db.execute("""
                CREATE TABLE IF NOT EXISTS model_integrity_baselines (
                    agent_id TEXT PRIMARY KEY,
                    model_name TEXT NOT NULL,
                    model_hash TEXT NOT NULL,
                    embedding_baseline TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

            # Model Integrity Events
            await db.execute("""
                CREATE TABLE IF NOT EXISTS model_integrity_events (
                    event_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    baseline_value TEXT NOT NULL,
                    current_value TEXT NOT NULL,
                    drift_score REAL NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)

            # Agent Capability Profiles
            await db.execute("""
                CREATE TABLE IF NOT EXISTS agent_capability_profiles (
                    agent_id TEXT PRIMARY KEY,
                    allowed_tools TEXT NOT NULL,
                    allowed_destinations TEXT NOT NULL,
                    learned_at REAL NOT NULL
                )
            """)

            # Capability Violations
            await db.execute("""
                CREATE TABLE IF NOT EXISTS capability_violations (
                    violation_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)

            # Supply Chain Dependencies
            await db.execute("""
                CREATE TABLE IF NOT EXISTS supply_chain_dependencies (
                    dependency_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    dependency_name TEXT NOT NULL,
                    expected_version TEXT NOT NULL,
                    expected_hash TEXT NOT NULL,
                    certificate_subject TEXT,
                    registered_at REAL NOT NULL
                )
            """)

            # Supply Chain Events
            await db.execute("""
                CREATE TABLE IF NOT EXISTS supply_chain_events (
                    event_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    dependency_name TEXT NOT NULL,
                    current_version TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    issue_type TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)

            # Prompt Mutation History
            await db.execute("""
                CREATE TABLE IF NOT EXISTS prompt_mutation_history (
                    record_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    original_prompt TEXT NOT NULL,
                    mutated_prompt TEXT NOT NULL,
                    levenshtein_distance INTEGER NOT NULL,
                    similarity_score REAL NOT NULL,
                    is_anomaly INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)

            # Attack Graph Nodes
            await db.execute("""
                CREATE TABLE IF NOT EXISTS attack_graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    compromise_likelihood REAL NOT NULL,
                    state TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

            # Attack Graph Edges
            await db.execute("""
                CREATE TABLE IF NOT EXISTS attack_graph_edges (
                    edge_id TEXT PRIMARY KEY,
                    source_agent_id TEXT NOT NULL,
                    target_agent_id TEXT NOT NULL,
                    propagation_probability REAL NOT NULL,
                    delegation_count INTEGER NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

            # Remediation Scripts
            await db.execute("""
                CREATE TABLE IF NOT EXISTS remediation_scripts (
                    script_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    script_type TEXT NOT NULL,
                    code TEXT NOT NULL,
                    generated_at REAL NOT NULL
                )
            """)

            # Tamper Proof Incidents
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tamper_proof_incidents (
                    incident_id TEXT PRIMARY KEY,
                    signature TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    merkle_proof TEXT,
                    signed_at REAL NOT NULL
                )
            """)

            # Autonomous Remediation Chains
            await db.execute("""
                CREATE TABLE IF NOT EXISTS autonomous_remediation_chains (
                    chain_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    steps_json TEXT NOT NULL,
                    current_step INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

            # Behavioral Footprint Scores
            await db.execute("""
                CREATE TABLE IF NOT EXISTS behavioral_footprint_scores (
                    agent_id TEXT PRIMARY KEY,
                    repetition_score REAL NOT NULL,
                    entropy_score REAL NOT NULL,
                    timing_regularity REAL NOT NULL,
                    tool_predictability REAL NOT NULL,
                    spoofing_likelihood REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

            await db.commit()
        logger.info("Database schemas verified/created.")

    async def register_agent(self, profile: AgentProfile) -> None:
        """Upserts an agent profile into the registry.

        Args:
            profile: AgentProfile to register.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO agents (agent_id, name, permitted_tools, permitted_agents, baseline_call_rate, status, registered_at, armoriq_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    name=excluded.name,
                    permitted_tools=excluded.permitted_tools,
                    permitted_agents=excluded.permitted_agents,
                    baseline_call_rate=excluded.baseline_call_rate,
                    status=excluded.status,
                    armoriq_id=COALESCE(excluded.armoriq_id, agents.armoriq_id)
                """,
                (
                    profile.agent_id,
                    profile.name,
                    json.dumps(profile.permitted_tools),
                    json.dumps(profile.permitted_agents),
                    profile.baseline_call_rate,
                    profile.status.value,
                    profile.registered_at.isoformat(),
                    profile.armoriq_id,
                ),
            )
            await db.commit()
        logger.info(f"Registered/updated agent profile: {profile.agent_id}")

    async def get_agent(self, agent_id: str) -> Optional[AgentProfile]:
        """Fetches an agent profile by agent_id.

        Args:
            agent_id: The unique identifier.

        Returns:
            The AgentProfile if found, else None.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                
                return AgentProfile(
                    agent_id=row["agent_id"],
                    name=row["name"],
                    permitted_tools=json.loads(row["permitted_tools"]),
                    permitted_agents=json.loads(row["permitted_agents"]),
                    baseline_call_rate=row["baseline_call_rate"],
                    status=AgentStatus(row["status"]),
                    registered_at=datetime.fromisoformat(row["registered_at"]),
                    armoriq_id=row["armoriq_id"],
                )

    async def list_agents(self) -> List[AgentProfile]:
        """Lists all agents in the registry."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM agents") as cursor:
                rows = await cursor.fetchall()
                agents = []
                for row in rows:
                    agents.append(
                        AgentProfile(
                            agent_id=row["agent_id"],
                            name=row["name"],
                            permitted_tools=json.loads(row["permitted_tools"]),
                            permitted_agents=json.loads(row["permitted_agents"]),
                            baseline_call_rate=row["baseline_call_rate"],
                            status=AgentStatus(row["status"]),
                            registered_at=datetime.fromisoformat(row["registered_at"]),
                            armoriq_id=row["armoriq_id"],
                        )
                    )
                return agents

    async def update_status(self, agent_id: str, status: AgentStatus) -> None:
        """Updates the status of an agent (e.g. to QUARANTINED).

        Args:
            agent_id: Agent identifier.
            status: New AgentStatus.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE agents SET status = ? WHERE agent_id = ?",
                (status.value, agent_id),
            )
            await db.commit()
        logger.info(f"Updated agent status for {agent_id} to {status.value}")

    async def log_event(self, event: AgentEvent, score: float = 0.0) -> None:
        """Logs an observed agent event.

        Args:
            event: The AgentEvent to record.
            score: The anomaly score assigned to this event.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO events (agent_id, event_type, target, payload, payload_size, score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.agent_id,
                    event.event_type.value,
                    event.target,
                    event.payload,
                    event.payload_size,
                    score,
                    event.timestamp,
                ),
            )
            await db.commit()

    async def get_events(self, agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetches event history for an agent.

        Args:
            agent_id: The agent to fetch events for.
            limit: Maximum events to return.

        Returns:
            A list of dictionary representations of events.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM events WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
                (agent_id, limit),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def get_event_count(self, agent_id: str) -> int:
        """Retrieves the total number of events recorded for an agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            Total count of events.
        """
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT COUNT(*) FROM events WHERE agent_id = ?", (agent_id,)
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0

    async def log_incident(self, incident: IncidentRecord) -> None:
        """Registers a security incident in the database.

        Args:
            incident: The IncidentRecord detailing the breach/anomaly.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO incidents (incident_id, agent_id, threat_type, score, action_taken, policy_decision, explanation, timestamp, detection_result, event_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.agent_id,
                    incident.threat_type.value,
                    incident.detection_result.score,
                    incident.action_taken,
                    incident.policy_decision.value,
                    incident.explanation,
                    incident.timestamp,
                    incident.detection_result.model_dump_json(),
                    incident.event.model_dump_json(),
                ),
            )
            await db.commit()
        logger.info(f"Logged security incident: {incident.incident_id} for agent {incident.agent_id}")

    async def get_incidents(self, limit: int = 50) -> List[IncidentRecord]:
        """Retrieves a list of recent incidents.

        Args:
            limit: Max incidents to return.

        Returns:
            List of IncidentRecords.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                incidents = []
                for row in rows:
                    detection_dict = json.loads(row["detection_result"])
                    event_dict = json.loads(row["event_data"])
                    
                    incidents.append(
                        IncidentRecord(
                            incident_id=row["incident_id"],
                            agent_id=row["agent_id"],
                            threat_type=ThreatType(row["threat_type"]),
                            detection_result=DetectionResult(**detection_dict),
                            policy_decision=PolicyDecision(row["policy_decision"]),
                            action_taken=row["action_taken"],
                            explanation=row["explanation"],
                            timestamp=row["timestamp"],
                            event=AgentEvent(**event_dict),
                        )
                    )
                return incidents

    async def update_incident_explanation(self, incident_id: str, explanation: str) -> None:
        """Updates the plain English explanation for an incident.

        Args:
            incident_id: ID of the incident.
            explanation: Plain English generated explanation.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE incidents SET explanation = ? WHERE incident_id = ?",
                (explanation, incident_id),
            )
            await db.commit()
        logger.info(f"Updated explanation for incident {incident_id}")

    async def log_policy_decision(self, entry: AuditEntry) -> None:
        """Stores a policy decision audit entry in the local DB.

        Args:
            entry: The AuditEntry to record.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO policy_decisions (entry_id, agent_id, decision, action, score, threat_type, timestamp, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.entry_id,
                    entry.agent_id,
                    entry.decision.value,
                    entry.action,
                    entry.score,
                    entry.threat_type.value,
                    entry.timestamp,
                    entry.source,
                ),
            )
            await db.commit()

    async def get_audit_log(self, limit: int = 50) -> List[AuditEntry]:
        """Fetches the local audit log trail.

        Args:
            limit: Maximum entries to return.

        Returns:
            List of AuditEntries.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM policy_decisions ORDER BY timestamp DESC LIMIT ?", (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                entries = []
                for row in rows:
                    entries.append(
                        AuditEntry(
                            entry_id=row["entry_id"],
                            agent_id=row["agent_id"],
                            decision=PolicyDecision(row["decision"]),
                            action=row["action"],
                            score=row["score"],
                            threat_type=ThreatType(row["threat_type"]),
                            timestamp=row["timestamp"],
                            source=row["source"],
                        )
                    )
                return entries

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Telegram Governed Runtime CRUD Methods
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def register_telegram_user(self, user: TelegramUser) -> None:
        """Upserts a Telegram user into the RBAC registry."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO telegram_users (telegram_id, username, display_name, role, is_active, registered_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(telegram_id) DO UPDATE SET
                    username=excluded.username,
                    display_name=excluded.display_name,
                    role=excluded.role,
                    is_active=excluded.is_active,
                    last_seen=excluded.last_seen
                """,
                (
                    user.telegram_id,
                    user.username,
                    user.display_name,
                    user.role.value,
                    1 if user.is_active else 0,
                    user.registered_at,
                    user.last_seen,
                ),
            )
            await db.commit()
        logger.info(f"Registered/updated Telegram user: {user.telegram_id} ({user.role.value})")

    async def get_telegram_user(self, telegram_id: int) -> Optional[TelegramUser]:
        """Fetches a Telegram user by their Telegram ID."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM telegram_users WHERE telegram_id = ?", (telegram_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return TelegramUser(
                    telegram_id=row["telegram_id"],
                    username=row["username"],
                    display_name=row["display_name"],
                    role=TelegramRole(row["role"]),
                    is_active=bool(row["is_active"]),
                    registered_at=row["registered_at"],
                    last_seen=row["last_seen"],
                )

    async def list_telegram_users(self) -> List[TelegramUser]:
        """Lists all registered Telegram users."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM telegram_users ORDER BY registered_at DESC") as cursor:
                rows = await cursor.fetchall()
                return [
                    TelegramUser(
                        telegram_id=row["telegram_id"],
                        username=row["username"],
                        display_name=row["display_name"],
                        role=TelegramRole(row["role"]),
                        is_active=bool(row["is_active"]),
                        registered_at=row["registered_at"],
                        last_seen=row["last_seen"],
                    )
                    for row in rows
                ]

    async def update_telegram_user_last_seen(self, telegram_id: int) -> None:
        """Updates the last_seen timestamp for a Telegram user."""
        import time as _time
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE telegram_users SET last_seen = ? WHERE telegram_id = ?",
                (_time.time(), telegram_id),
            )
            await db.commit()

    async def create_approval_request(self, request: ApprovalRequest) -> None:
        """Creates a new governance approval request."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO approval_requests
                (request_id, incident_id, agent_id, threat_type, threat_score, proposed_action, status, requested_at, resolved_at, resolved_by, telegram_message_id, chat_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.request_id,
                    request.incident_id,
                    request.agent_id,
                    request.threat_type.value,
                    request.threat_score,
                    request.proposed_action,
                    request.status.value,
                    request.requested_at,
                    request.resolved_at,
                    request.resolved_by,
                    request.telegram_message_id,
                    request.chat_id,
                ),
            )
            await db.commit()
        logger.info(f"Created approval request: {request.request_id} for incident {request.incident_id}")

    async def resolve_approval_request(
        self, request_id: str, status: ApprovalStatus, resolved_by: int
    ) -> Optional[ApprovalRequest]:
        """Resolves a pending approval request and returns the updated record."""
        import time as _time
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE approval_requests SET status = ?, resolved_at = ?, resolved_by = ? WHERE request_id = ?",
                (status.value, _time.time(), resolved_by, request_id),
            )
            await db.commit()

            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                return ApprovalRequest(
                    request_id=row["request_id"],
                    incident_id=row["incident_id"],
                    agent_id=row["agent_id"],
                    threat_type=ThreatType(row["threat_type"]),
                    threat_score=row["threat_score"],
                    proposed_action=row["proposed_action"],
                    status=ApprovalStatus(row["status"]),
                    requested_at=row["requested_at"],
                    resolved_at=row["resolved_at"],
                    resolved_by=row["resolved_by"],
                    telegram_message_id=row["telegram_message_id"],
                    chat_id=row["chat_id"],
                )

    async def get_pending_approvals(self) -> List[ApprovalRequest]:
        """Returns all pending approval requests."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM approval_requests WHERE status = 'PENDING' ORDER BY requested_at DESC"
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    ApprovalRequest(
                        request_id=row["request_id"],
                        incident_id=row["incident_id"],
                        agent_id=row["agent_id"],
                        threat_type=ThreatType(row["threat_type"]),
                        threat_score=row["threat_score"],
                        proposed_action=row["proposed_action"],
                        status=ApprovalStatus(row["status"]),
                        requested_at=row["requested_at"],
                        resolved_at=row["resolved_at"],
                        resolved_by=row["resolved_by"],
                        telegram_message_id=row["telegram_message_id"],
                        chat_id=row["chat_id"],
                    )
                    for row in rows
                ]

    async def get_approval_stats(self) -> Dict[str, int]:
        """Returns counts of approval requests by status."""
        async with aiosqlite.connect(self.db_path) as db:
            stats = {}
            for status in ApprovalStatus:
                async with db.execute(
                    "SELECT COUNT(*) FROM approval_requests WHERE status = ?",
                    (status.value,),
                ) as cursor:
                    row = await cursor.fetchone()
                    stats[status.value] = row[0] if row else 0
            return stats

    async def log_governance_action(self, action: GovernanceAction) -> None:
        """Records a governance action in the audit trail."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO governance_actions (action_id, request_id, telegram_user_id, action, timestamp, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    action.action_id,
                    action.request_id,
                    action.telegram_user_id,
                    action.action,
                    action.timestamp,
                    action.reason,
                ),
            )
            await db.commit()
        logger.info(f"Logged governance action: {action.action} by user {action.telegram_user_id}")

    async def log_notification(self, record: NotificationRecord) -> None:
        """Tracks a sent notification."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO incident_notifications
                (notification_id, incident_id, chat_id, notification_type, content_summary, sent_at, delivered)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.notification_id,
                    record.incident_id,
                    record.chat_id,
                    record.notification_type,
                    record.content_summary,
                    record.sent_at,
                    1 if record.delivered else 0,
                ),
            )
            await db.commit()

    async def get_telegram_session_count(self) -> int:
        """Returns the count of active Telegram sessions."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT COUNT(*) FROM telegram_sessions WHERE is_active = 1"
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0

    # VIGIL 2.0 CRUD Methods

    async def get_model_integrity_baseline(self, agent_id: str) -> Optional[ModelIntegrityBaseline]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM model_integrity_baselines WHERE agent_id = ?",
                (agent_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return ModelIntegrityBaseline(
                        agent_id=row["agent_id"],
                        model_name=row["model_name"],
                        model_hash=row["model_hash"],
                        embedding_baseline=row["embedding_baseline"],
                        updated_at=row["updated_at"],
                    )
        return None

    async def save_model_integrity_baseline(self, baseline: ModelIntegrityBaseline) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO model_integrity_baselines (agent_id, model_name, model_hash, embedding_baseline, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    baseline.agent_id,
                    baseline.model_name,
                    baseline.model_hash,
                    baseline.embedding_baseline,
                    baseline.updated_at,
                ),
            )
            await db.commit()

    async def log_model_integrity_event(self, event: ModelIntegrityEvent) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO model_integrity_events (event_id, agent_id, metric_name, baseline_value, current_value, drift_score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.agent_id,
                    event.metric_name,
                    event.baseline_value,
                    event.current_value,
                    event.drift_score,
                    event.timestamp,
                ),
            )
            await db.commit()

    async def get_model_integrity_events(self, agent_id: str) -> List[ModelIntegrityEvent]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM model_integrity_events WHERE agent_id = ? ORDER BY timestamp DESC",
                (agent_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    ModelIntegrityEvent(
                        event_id=row["event_id"],
                        agent_id=row["agent_id"],
                        metric_name=row["metric_name"],
                        baseline_value=row["baseline_value"],
                        current_value=row["current_value"],
                        drift_score=row["drift_score"],
                        timestamp=row["timestamp"],
                    )
                    for row in rows
                ]

    async def get_capability_profile(self, agent_id: str) -> Optional[CapabilityProfile]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM agent_capability_profiles WHERE agent_id = ?",
                (agent_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return CapabilityProfile(
                        agent_id=row["agent_id"],
                        allowed_tools=json.loads(row["allowed_tools"]),
                        allowed_destinations=json.loads(row["allowed_destinations"]),
                        learned_at=row["learned_at"],
                    )
        return None

    async def save_capability_profile(self, profile: CapabilityProfile) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO agent_capability_profiles (agent_id, allowed_tools, allowed_destinations, learned_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    profile.agent_id,
                    json.dumps(profile.allowed_tools),
                    json.dumps(profile.allowed_destinations),
                    profile.learned_at,
                ),
            )
            await db.commit()

    async def log_capability_violation(self, violation: CapabilityViolation) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO capability_violations (violation_id, agent_id, action_type, target, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    violation.violation_id,
                    violation.agent_id,
                    violation.action_type,
                    violation.target,
                    violation.timestamp,
                ),
            )
            await db.commit()

    async def get_capability_violations(self, agent_id: str) -> List[CapabilityViolation]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM capability_violations WHERE agent_id = ? ORDER BY timestamp DESC",
                (agent_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    CapabilityViolation(
                        violation_id=row["violation_id"],
                        agent_id=row["agent_id"],
                        action_type=row["action_type"],
                        target=row["target"],
                        timestamp=row["timestamp"],
                    )
                    for row in rows
                ]

    async def get_supply_chain_dependencies(self, agent_id: str) -> List[SupplyChainDependency]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM supply_chain_dependencies WHERE agent_id = ?",
                (agent_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    SupplyChainDependency(
                        dependency_id=row["dependency_id"],
                        agent_id=row["agent_id"],
                        dependency_name=row["dependency_name"],
                        expected_version=row["expected_version"],
                        expected_hash=row["expected_hash"],
                        certificate_subject=row["certificate_subject"],
                        registered_at=row["registered_at"],
                    )
                    for row in rows
                ]

    async def save_supply_chain_dependency(self, dep: SupplyChainDependency) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO supply_chain_dependencies (dependency_id, agent_id, dependency_name, expected_version, expected_hash, certificate_subject, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dep.dependency_id,
                    dep.agent_id,
                    dep.dependency_name,
                    dep.expected_version,
                    dep.expected_hash,
                    dep.certificate_subject,
                    dep.registered_at,
                ),
            )
            await db.commit()

    async def log_supply_chain_event(self, event: SupplyChainEvent) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO supply_chain_events (event_id, agent_id, dependency_name, current_version, current_hash, issue_type, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.agent_id,
                    event.dependency_name,
                    event.current_version,
                    event.current_hash,
                    event.issue_type,
                    event.timestamp,
                ),
            )
            await db.commit()

    async def get_supply_chain_events(self, agent_id: str) -> List[SupplyChainEvent]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM supply_chain_events WHERE agent_id = ? ORDER BY timestamp DESC",
                (agent_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    SupplyChainEvent(
                        event_id=row["event_id"],
                        agent_id=row["agent_id"],
                        dependency_name=row["dependency_name"],
                        current_version=row["current_version"],
                        current_hash=row["current_hash"],
                        issue_type=row["issue_type"],
                        timestamp=row["timestamp"],
                    )
                    for row in rows
                ]

    async def log_prompt_mutation(self, record: PromptMutationRecord) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO prompt_mutation_history (record_id, agent_id, original_prompt, mutated_prompt, levenshtein_distance, similarity_score, is_anomaly, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.record_id,
                    record.agent_id,
                    record.original_prompt,
                    record.mutated_prompt,
                    record.levenshtein_distance,
                    record.similarity_score,
                    1 if record.is_anomaly else 0,
                    record.timestamp,
                ),
            )
            await db.commit()

    async def get_prompt_mutations(self, agent_id: str) -> List[PromptMutationRecord]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM prompt_mutation_history WHERE agent_id = ? ORDER BY timestamp DESC",
                (agent_id,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [
                    PromptMutationRecord(
                        record_id=row["record_id"],
                        agent_id=row["agent_id"],
                        original_prompt=row["original_prompt"],
                        mutated_prompt=row["mutated_prompt"],
                        levenshtein_distance=row["levenshtein_distance"],
                        similarity_score=row["similarity_score"],
                        is_anomaly=bool(row["is_anomaly"]),
                        timestamp=row["timestamp"],
                    )
                    for row in rows
                ]

    async def save_attack_graph_node(self, node: AttackGraphNode) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO attack_graph_nodes (node_id, agent_id, compromise_likelihood, state, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    node.node_id,
                    node.agent_id,
                    node.compromise_likelihood,
                    node.state,
                    node.updated_at,
                ),
            )
            await db.commit()

    async def get_attack_graph_nodes(self) -> List[AttackGraphNode]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM attack_graph_nodes") as cursor:
                rows = await cursor.fetchall()
                return [
                    AttackGraphNode(
                        node_id=row["node_id"],
                        agent_id=row["agent_id"],
                        compromise_likelihood=row["compromise_likelihood"],
                        state=row["state"],
                        updated_at=row["updated_at"],
                    )
                    for row in rows
                ]

    async def save_attack_graph_edge(self, edge: AttackGraphEdge) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO attack_graph_edges (edge_id, source_agent_id, target_agent_id, propagation_probability, delegation_count, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    edge.edge_id,
                    edge.source_agent_id,
                    edge.target_agent_id,
                    edge.propagation_probability,
                    edge.delegation_count,
                    edge.updated_at,
                ),
            )
            await db.commit()

    async def get_attack_graph_edges(self) -> List[AttackGraphEdge]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM attack_graph_edges") as cursor:
                rows = await cursor.fetchall()
                return [
                    AttackGraphEdge(
                        edge_id=row["edge_id"],
                        source_agent_id=row["source_agent_id"],
                        target_agent_id=row["target_agent_id"],
                        propagation_probability=row["propagation_probability"],
                        delegation_count=row["delegation_count"],
                        updated_at=row["updated_at"],
                    )
                    for row in rows
                ]

    async def clear_attack_graph(self) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM attack_graph_nodes")
            await db.execute("DELETE FROM attack_graph_edges")
            await db.commit()

    async def save_remediation_script(self, script: RemediationScript) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO remediation_scripts (script_id, incident_id, script_type, code, generated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    script.script_id,
                    script.incident_id,
                    script.script_type,
                    script.code,
                    script.generated_at,
                ),
            )
            await db.commit()

    async def get_remediation_script(self, incident_id: str) -> Optional[RemediationScript]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM remediation_scripts WHERE incident_id = ?",
                (incident_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return RemediationScript(
                        script_id=row["script_id"],
                        incident_id=row["incident_id"],
                        script_type=row["script_type"],
                        code=row["code"],
                        generated_at=row["generated_at"],
                    )
        return None

    async def save_tamper_proof_incident(self, incident: TamperProofIncident) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO tamper_proof_incidents (incident_id, signature, public_key_pem, merkle_proof, signed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.signature,
                    incident.public_key_pem,
                    incident.merkle_proof,
                    incident.signed_at,
                ),
            )
            await db.commit()

    async def get_tamper_proof_incident(self, incident_id: str) -> Optional[TamperProofIncident]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM tamper_proof_incidents WHERE incident_id = ?",
                (incident_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return TamperProofIncident(
                        incident_id=row["incident_id"],
                        signature=row["signature"],
                        public_key_pem=row["public_key_pem"],
                        merkle_proof=row["merkle_proof"],
                        signed_at=row["signed_at"],
                    )
        return None

    async def save_remediation_chain(self, chain: RemediationChain) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO autonomous_remediation_chains (chain_id, incident_id, agent_id, steps_json, current_step, status, started_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain.chain_id,
                    chain.incident_id,
                    chain.agent_id,
                    chain.steps_json,
                    chain.current_step,
                    chain.status,
                    chain.started_at,
                    chain.updated_at,
                ),
            )
            await db.commit()

    async def get_remediation_chain(self, incident_id: str) -> Optional[RemediationChain]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM autonomous_remediation_chains WHERE incident_id = ?",
                (incident_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return RemediationChain(
                        chain_id=row["chain_id"],
                        incident_id=row["incident_id"],
                        agent_id=row["agent_id"],
                        steps_json=row["steps_json"],
                        current_step=row["current_step"],
                        status=row["status"],
                        started_at=row["started_at"],
                        updated_at=row["updated_at"],
                    )
        return None

    async def save_behavioral_footprint_score(self, score: BehavioralFootprintScore) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO behavioral_footprint_scores (agent_id, repetition_score, entropy_score, timing_regularity, tool_predictability, spoofing_likelihood, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    score.agent_id,
                    score.repetition_score,
                    score.entropy_score,
                    score.timing_regularity,
                    score.tool_predictability,
                    score.spoofing_likelihood,
                    score.updated_at,
                ),
            )
            await db.commit()

    async def get_behavioral_footprint_score(self, agent_id: str) -> Optional[BehavioralFootprintScore]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM behavioral_footprint_scores WHERE agent_id = ?",
                (agent_id,),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return BehavioralFootprintScore(
                        agent_id=row["agent_id"],
                        repetition_score=row["repetition_score"],
                        entropy_score=row["entropy_score"],
                        timing_regularity=row["timing_regularity"],
                        tool_predictability=row["tool_predictability"],
                        spoofing_likelihood=row["spoofing_likelihood"],
                        updated_at=row["updated_at"],
                    )
        return None
