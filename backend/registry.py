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
