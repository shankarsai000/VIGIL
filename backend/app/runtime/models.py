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
    MODEL_POISONING = "MODEL_POISONING"
    PROMPT_MUTATION = "PROMPT_MUTATION"
    CAPABILITY_VIOLATION = "CAPABILITY_VIOLATION"
    SUPPLY_CHAIN_COMPROMISE = "SUPPLY_CHAIN_COMPROMISE"
    BEHAVIORAL_SPOOFING = "BEHAVIORAL_SPOOFING"
    ATTACK_PROPAGATION = "ATTACK_PROPAGATION"


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
    TELEGRAM_STATUS = "TELEGRAM_STATUS"
    MODEL_INTEGRITY_ALERT = "MODEL_INTEGRITY_ALERT"
    CAPABILITY_VIOLATION_ALERT = "CAPABILITY_VIOLATION_ALERT"
    SUPPLY_CHAIN_ALERT = "SUPPLY_CHAIN_ALERT"
    ATTACK_GRAPH_UPDATE = "ATTACK_GRAPH_UPDATE"
    REMEDIATION_CHAIN_UPDATE = "REMEDIATION_CHAIN_UPDATE"
    EVIDENCE_CHAIN_UPDATE = "EVIDENCE_CHAIN_UPDATE"
    GOVERNANCE_UPDATE = "GOVERNANCE_UPDATE"


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


class IncidentState(str, Enum):
    """State of an incident in the governance workflow."""
    NEW = "NEW"
    WATCHLIST = "WATCHLIST"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    QUARANTINED = "QUARANTINED"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"
    RECOVERED = "RECOVERED"


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
    state: IncidentState = Field(default=IncidentState.NEW, description="Current state of the incident in governance workflow")


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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Telegram Governed Runtime Models
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class TelegramRole(str, Enum):
    """RBAC roles for Telegram governance operators."""
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    OBSERVER = "OBSERVER"
    EXECUTIVE = "EXECUTIVE"

    @classmethod
    def hierarchy_level(cls, role: "TelegramRole") -> int:
        """Returns numeric privilege level. Higher = more privileged."""
        levels = {
            cls.EXECUTIVE: 1,
            cls.OBSERVER: 2,
            cls.SECURITY_ANALYST: 3,
            cls.ADMIN: 4,
        }
        return levels.get(role, 0)

    def has_permission(self, required_role: "TelegramRole") -> bool:
        """Checks if this role meets the minimum required role level."""
        return TelegramRole.hierarchy_level(self) >= TelegramRole.hierarchy_level(required_role)




class ApprovalStatus(str, Enum):
    """Status of a governance approval request."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    INVESTIGATING = "INVESTIGATING"


class TelegramUser(BaseModel):
    """RBAC user model for Telegram governance operators."""
    telegram_id: int = Field(description="Telegram user ID")
    username: str = Field(default="", description="Telegram username")
    display_name: str = Field(default="", description="Display name of the operator")
    role: TelegramRole = Field(default=TelegramRole.OBSERVER, description="RBAC role")
    is_active: bool = Field(default=True, description="Whether this user is active")
    registered_at: float = Field(default_factory=time.time, description="Registration timestamp")
    last_seen: float = Field(default_factory=time.time, description="Last activity timestamp")


class ApprovalRequest(BaseModel):
    """Pending governance approval request sent to Telegram operators."""
    request_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique approval request ID")
    incident_id: str = Field(description="Associated incident ID")
    agent_id: str = Field(description="Agent subject to governance action")
    threat_type: ThreatType = Field(description="Detected threat type")
    threat_score: float = Field(description="VIGIL threat score")
    proposed_action: str = Field(description="Action awaiting approval")
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING, description="Current approval status")
    requested_at: float = Field(default_factory=time.time, description="When approval was requested")
    resolved_at: Optional[float] = Field(default=None, description="When approval was resolved")
    resolved_by: Optional[int] = Field(default=None, description="Telegram user ID who resolved")
    telegram_message_id: Optional[int] = Field(default=None, description="Telegram message ID of the approval card")
    chat_id: Optional[int] = Field(default=None, description="Telegram chat ID where approval was sent")


class TelegramGovernanceAction(BaseModel):
    """Detailed record of a Telegram governance action with full state tracking."""
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique governance action ID")
    incident_id: str = Field(description="Associated incident ID")
    action: str = Field(description="Action taken: APPROVE, DENY, INVESTIGATE")
    operator_id: int = Field(description="Telegram user ID of the operator")
    telegram_username: str = Field(default="", description="Telegram username of the operator")
    timestamp: float = Field(default_factory=time.time, description="When the action was taken")
    governance_result: str = Field(default="", description="Result of governance validation")
    resulting_state: str = Field(default="", description="Resulting incident state after action")
    armoriq_decision: str = Field(default="", description="ArmorIQ's validation decision")
    remediation_action: str = Field(default="", description="Remediation action executed (if any)")


class GovernanceAction(BaseModel):
    """Records approval/denial actions taken via Telegram governance."""
    action_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique governance action ID")
    request_id: str = Field(description="Associated approval request ID")
    telegram_user_id: int = Field(description="Telegram user who performed the action")
    action: str = Field(description="Action taken: APPROVE, DENY, INVESTIGATE")
    timestamp: float = Field(default_factory=time.time, description="When the action was taken")
    reason: str = Field(default="", description="Optional reason for the action")


class NotificationRecord(BaseModel):
    """Tracks sent alert notifications to Telegram."""
    notification_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique notification ID")
    incident_id: str = Field(default="", description="Associated incident ID")
    chat_id: int = Field(description="Telegram chat ID notification was sent to")
    notification_type: str = Field(description="Type: ALERT, APPROVAL_CARD, SNAPSHOT, ESCALATION")
    content_summary: str = Field(default="", description="Brief summary of what was sent")
    sent_at: float = Field(default_factory=time.time, description="When notification was sent")
    delivered: bool = Field(default=True, description="Whether delivery was confirmed")


class GovernanceVerdict(str, Enum):
    """Result of governance evaluation for a Telegram request."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ModelIntegrityBaseline(BaseModel):
    agent_id: str
    model_name: str
    model_hash: str
    embedding_baseline: str  # JSON-serialized list of floats
    updated_at: float = Field(default_factory=time.time)


class ModelIntegrityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    metric_name: str  # e.g., 'hash_mismatch', 'cosine_drift'
    baseline_value: str
    current_value: str
    drift_score: float
    timestamp: float = Field(default_factory=time.time)


class CapabilityProfile(BaseModel):
    agent_id: str
    allowed_tools: List[str] = Field(default_factory=list)
    allowed_destinations: List[str] = Field(default_factory=list)
    learned_at: float = Field(default_factory=time.time)


class CapabilityViolation(BaseModel):
    violation_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    action_type: str  # 'TOOL' or 'DESTINATION'
    target: str
    timestamp: float = Field(default_factory=time.time)


class SupplyChainDependency(BaseModel):
    dependency_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    dependency_name: str
    expected_version: str
    expected_hash: str
    certificate_subject: Optional[str] = None
    registered_at: float = Field(default_factory=time.time)


class SupplyChainEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    dependency_name: str
    current_version: str
    current_hash: str
    issue_type: str  # 'HASH_MISMATCH', 'VERSION_DRIFT', 'CERT_INVALID'
    timestamp: float = Field(default_factory=time.time)


class PromptMutationRecord(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    original_prompt: str
    mutated_prompt: str
    levenshtein_distance: int
    similarity_score: float
    is_anomaly: bool
    timestamp: float = Field(default_factory=time.time)


class AttackGraphNode(BaseModel):
    node_id: str
    agent_id: str
    compromise_likelihood: float
    state: str  # 'NORMAL', 'COMPROMISED', 'SUSPECT'
    updated_at: float = Field(default_factory=time.time)


class AttackGraphEdge(BaseModel):
    edge_id: str = Field(default_factory=lambda: str(uuid4()))
    source_agent_id: str
    target_agent_id: str
    propagation_probability: float
    delegation_count: int
    updated_at: float = Field(default_factory=time.time)


class RemediationScript(BaseModel):
    script_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    script_type: str  # 'BASH', 'PYTHON'
    code: str
    generated_at: float = Field(default_factory=time.time)


class TamperProofIncident(BaseModel):
    incident_id: str
    signature: str
    public_key_pem: str
    merkle_proof: Optional[str] = None
    signed_at: float = Field(default_factory=time.time)


class RemediationChain(BaseModel):
    chain_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    agent_id: str
    steps_json: str  # JSON list of dicts with status
    current_step: int
    status: str  # 'PLANNING', 'EXECUTING', 'COMPLETED', 'FAILED'
    started_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


class BehavioralFootprintScore(BaseModel):
    agent_id: str
    repetition_score: float
    entropy_score: float
    timing_regularity: float
    tool_predictability: float
    spoofing_likelihood: float
    updated_at: float = Field(default_factory=time.time)

