"""VIGIL Pydantic models and enums.

Defines the core type system and data schemas used throughout VIGIL for data validation,
API communication, database persistence, and WebSocket broadcasting.
"""

from enum import Enum
import time
from uuid import uuid4
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNAUTHORIZED_DELEGATION = "UNAUTHORIZED_DELEGATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    RATE_ANOMALY = "RATE_ANOMALY"
    VOLUME_ANOMALY = "VOLUME_ANOMALY"


class Confidence(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_score(cls, score: float) -> "Confidence":
        """Maps a float score to the appropriate confidence level."""
        if score >= 0.85:
            return cls.CRITICAL
        elif score >= 0.65:
            return cls.HIGH
        elif score >= 0.45:
            return cls.MEDIUM
        else:
            return cls.LOW


class AgentStatus(str, Enum):
    NORMAL = "NORMAL"
    QUARANTINED = "QUARANTINED"
    ALERT = "ALERT"
    REVOKED = "REVOKED"


class EventType(str, Enum):
    QUERY = "QUERY"
    TOOL_CALL = "TOOL_CALL"
    AGENT_DELEGATION = "AGENT_DELEGATION"
    DATA_ACCESS = "DATA_ACCESS"
    HEARTBEAT = "HEARTBEAT"


class PolicyDecision(str, Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    ESCALATE = "ESCALATE"


class WSEventType(str, Enum):
    AGENT_UPDATE = "AGENT_UPDATE"
    INCIDENT_DETECTED = "INCIDENT_DETECTED"
    POLICY_DECISION = "POLICY_DECISION"
    REMEDIATION_EXECUTED = "REMEDIATION_EXECUTED"
    EXPLANATION_READY = "EXPLANATION_READY"
    AUDIT_LOG_ENTRY = "AUDIT_LOG_ENTRY"


class AgentProfile(BaseModel):
    agent_id: str = Field(description="Unique identifier for the agent")
    name: str = Field(description="Display name of the agent")
    permitted_tools: List[str] = Field(default_factory=list, description="Tools the agent is allowed to invoke")
    permitted_agents: List[str] = Field(default_factory=list, description="Agents this agent is allowed to delegate tasks to")
    baseline_call_rate: float = Field(description="Expected baseline call rate in queries/minute")
    status: AgentStatus = Field(default=AgentStatus.NORMAL, description="Current operational status of the agent")
    registered_at: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of when the agent was registered")
    armoriq_id: Optional[str] = Field(default=None, description="Identifier mapped in ArmorIQ registry")


class AgentEvent(BaseModel):
    agent_id: str = Field(description="Identifier of the agent that produced the event")
    event_type: EventType = Field(description="Type of the agent activity")
    target: str = Field(description="Target resource, tool, or delegate agent of the operation")
    payload: str = Field(description="Input payload, query, or arguments string")
    payload_size: int = Field(description="Size of the payload in bytes")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of the event occurrence")


class DetectionResult(BaseModel):
    score: float = Field(description="Combined anomaly/threat score between 0.0 and 1.0")
    threat_type: ThreatType = Field(description="Detected threat type category")
    confidence: Confidence = Field(description="Confidence tier of the detection")
    rule_score: float = Field(description="Score contribution from rule engine (0.0 to 1.0)")
    ewma_score: float = Field(description="Score contribution from EWMA statistical baseline (0.0 to 1.0)")
    iforest_score: float = Field(description="Score contribution from Isolation Forest ML layer (0.0 to 1.0)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Metadata or evidence details from layers")


class ThreatContext(BaseModel):
    agent_id: str = Field(description="Identifier of the agent associated with the threat")
    threat_type: ThreatType = Field(description="Detected threat type category")
    score: float = Field(description="Combined anomaly/threat score")
    proposed_action: str = Field(description="Action suggested by VIGIL (QUARANTINE, ALERT, LOG)")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Details, metrics and events leading to detection")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of context generation")


class RemediationResult(BaseModel):
    agent_id: str = Field(description="Identifier of the agent remediated")
    action_taken: str = Field(description="Final action executed (QUARANTINE, ALERT, LOG, none)")
    policy_decision: PolicyDecision = Field(description="Decision returned by the ArmorIQ gate")
    threat_type: ThreatType = Field(description="Type of threat that triggered the response")
    score: float = Field(description="Final detection score")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of execution")
    incident_id: str = Field(description="Reference ID of the registered incident")


class IncidentRecord(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique UUID for this incident")
    agent_id: str = Field(description="Identifier of the agent involved in the incident")
    threat_type: ThreatType = Field(description="Detected threat type")
    detection_result: DetectionResult = Field(description="Full detection report")
    policy_decision: PolicyDecision = Field(description="ArmorIQ authorization decision")
    action_taken: str = Field(description="Remediation action taken")
    explanation: str = Field(default="", description="Plain English description of the incident")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of incident registration")
    event: AgentEvent = Field(description="Triggering agent event details")


class AuditEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique ID for this audit trail entry")
    agent_id: str = Field(description="Identifier of the agent involved")
    decision: PolicyDecision = Field(description="ArmorIQ gate decision")
    action: str = Field(description="Action taken by the remediation engine")
    score: float = Field(description="VIGIL security score")
    threat_type: ThreatType = Field(description="Threat category")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of the audit entry")
    source: str = Field(default="vigil", description="System source of the entry")


class WSEvent(BaseModel):
    type: WSEventType = Field(description="WebSocket event category")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of broadcast")
    agent_id: str = Field(description="Agent associated with this event")
    payload: Dict[str, Any] = Field(description="JSON-serializable content payload")


class ObservationResult(BaseModel):
    event: AgentEvent = Field(description="The observed event")
    detection_result: Optional[DetectionResult] = Field(default=None, description="The detection report, if threat evaluated")
    action_taken: Optional[str] = Field(default=None, description="Action taken, if any")
