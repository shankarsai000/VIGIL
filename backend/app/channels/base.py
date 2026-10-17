"""Base approval channel interfaces and protocol definitions.

Defines the contract for delivering governance approval requests and ingesting
interactive multi-party decisions from chat/collaboration platforms (e.g. Slack).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class RequestKind(str, Enum):
    """The operational nature of the governance approval."""
    CONTAINMENT = "CONTAINMENT"
    POLICY_PROPOSAL = "POLICY_PROPOSAL"


class DecisionAction(str, Enum):
    """The operator's explicit authorization decision."""
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class CallbackRejected(Exception):
    """Raised when an approval channel callback fails authentication or identity verification."""
    pass


@dataclass(frozen=True)
class ApproverIdentity:
    """Authenticated corporate approver identity bound to a verified identity provider."""
    provider: str
    subject_id: str
    email: str
    verified: bool = False


@dataclass
class ApprovalRequest:
    """Approval request payload delivered to the approval channel.
    
    Non-negotiable security invariant:
    Includes only summary telemetry and bounded metrics. Must NEVER contain
    raw argument values, planted secrets, or sensitive tool execution payloads.
    """
    request_id: str
    kind: RequestKind
    tier: str  # "LOW" or "HIGH"
    expires_at: float
    summary: Dict[str, Any] = field(default_factory=dict)
    summary_fields: Dict[str, Any] = field(default_factory=dict)
    dashboard_url: str = "http://localhost:5173"
    requester: Optional[str] = None
    nonce: str = ""

    def __post_init__(self):
        if not self.summary and self.summary_fields:
            self.summary = self.summary_fields
        elif not self.summary_fields and self.summary:
            self.summary_fields = self.summary


@dataclass(frozen=True)
class Decision:
    """Validated governance decision emitted by an approval channel."""
    request_id: str
    action: DecisionAction
    approver: ApproverIdentity
    received_at: float
    nonce: str


@dataclass(frozen=True)
class MessageRef:
    """Reference pointer to a delivered message on the remote channel."""
    channel: str
    message_ts: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class ApprovalChannel(ABC):
    """Abstract protocol for governance approval delivery and callback ingestion."""

    @abstractmethod
    def deliver(self, request: ApprovalRequest) -> MessageRef:
        """Delivers an approval request to the channel with interactive action buttons."""
        ...

    @abstractmethod
    def parse_callback(self, headers: Dict[str, str], raw_body: bytes) -> Decision:
        """Parses and verifies an interactive callback, returning an authenticated Decision or raising CallbackRejected."""
        ...

    @abstractmethod
    def update(self, ref: MessageRef, outcome_text: str, final_status: str = "RESOLVED") -> None:
        """Replaces interactive buttons with final decision status and author."""
        ...
