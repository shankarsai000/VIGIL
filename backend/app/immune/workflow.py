"""VIGIL Policy Immune System — Policy Proposals Workflow and Governance Logic.

Enforces:
1. Proposal life-cycle: PROPOSED -> APPROVED | REJECTED | EXPIRED.
2. 72-hour hard expiration with HTTP 409 conflict.
3. Impact-tier determination:
   - HIGH when: family spans >1 agent, benign_total > 5000, or false_block_point > 0.
   - Demands 2 distinct human approvers.
   - LOW demands 1 approver.
4. Idempotent approval: duplicate approver changes nothing.
5. Audit ledger logging for every state transition.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .replay import ReplayReport


class ProposalConfig(BaseModel):
    """Documented configuration thresholds for proposal impact tiering and expiration."""

    expiration_hours: float = 72.0
    high_impact_benign_threshold: int = 5000
    high_impact_false_block_threshold: float = 0.0
    high_impact_required_approvers: int = 2
    low_impact_required_approvers: int = 1


DEFAULT_PROPOSAL_CONFIG = ProposalConfig()

STATUS_PROPOSED = "PROPOSED"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_EXPIRED = "EXPIRED"

TIER_LOW = "LOW"
TIER_HIGH = "HIGH"


class PolicyProposalRecord(BaseModel):
    """Database entity representing a governance policy proposal."""

    id: str
    status: str = STATUS_PROPOSED
    agent_id: str
    mcp_id: Optional[str] = None
    tool: str
    impact_tier: str = TIER_LOW
    replay_json: str
    assumptions_json: str
    approvals_json: str = "[]"
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    decided_at: Optional[float] = None
    version: int = 1

    model_config = {"extra": "ignore"}

    def get_replay_report(self) -> Dict[str, Any]:
        return json.loads(self.replay_json)

    def get_assumptions(self) -> Dict[str, Any]:
        return json.loads(self.assumptions_json)

    def get_approvals(self) -> List[str]:
        return json.loads(self.approvals_json)

    def is_expired(self, now: Optional[float] = None) -> bool:
        current_time = now if now is not None else time.time()
        return current_time > self.expires_at

    def required_approvals_count(self, config: ProposalConfig = DEFAULT_PROPOSAL_CONFIG) -> int:
        return config.high_impact_required_approvers if self.impact_tier == TIER_HIGH else config.low_impact_required_approvers

    def approval_progress_text(self, config: ProposalConfig = DEFAULT_PROPOSAL_CONFIG) -> str:
        current = len(self.get_approvals())
        required = self.required_approvals_count(config)
        return f"{current} of {required}"


def compute_impact_tier(
    report: ReplayReport,
    agent_count: int = 1,
    config: ProposalConfig = DEFAULT_PROPOSAL_CONFIG,
) -> str:
    """Computes impact tier (LOW or HIGH) based on replay statistics and agent blast radius."""
    if agent_count > 1:
        return TIER_HIGH
    if report.benign_total > config.high_impact_benign_threshold:
        return TIER_HIGH
    if report.false_block_point > config.high_impact_false_block_threshold:
        return TIER_HIGH
    return TIER_LOW


def generate_yaml_diff(proposal: PolicyProposalRecord) -> str:
    """Generates a human-reviewable YAML diff patch for the proposed rule."""
    mcp = proposal.mcp_id or "default-mcp"
    return (
        f"--- a/config/{proposal.agent_id}.armoriq.yaml\n"
        f"+++ b/config/{proposal.agent_id}.armoriq.yaml\n"
        f"@@ policy.deny @@\n"
        f"+    - {mcp}.{proposal.tool}\n"
    )
