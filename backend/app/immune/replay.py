"""VIGIL Policy Immune System — Offline Pure Replay Engine & False-Block Bound.

Evaluates candidate security denial rules counterfactually against historical
action records using the exact one-sided Clopper-Pearson statistical bound.

CRITICAL DESIGN PRINCIPLE:
The engine is 100% pure. It makes NO network calls, performs NO database I/O,
and has NO side effects. All inputs and outputs are immutable data models.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from scipy.stats import beta as beta_dist

from .records import ActionRecord


class CandidateRule(BaseModel):
    """Proposed security rule denying one tool for one agent."""

    agent_id: str = Field(description="Agent subject to the proposed policy denial")
    tool: str = Field(description="Tool or operation name to be blocked")
    mcp_id: Optional[str] = Field(default=None, description="Optional MCP server scope")

    model_config = {"extra": "ignore"}


class ReplayAssumptions(BaseModel):
    """Foundational mathematical assumptions for the evaluated statistical bound."""

    exchangeability: str = (
        "Conditional exchangeability: future operational agent actions are assumed "
        "to follow the same distribution as the recorded traffic window for this agent and role."
    )
    assumed_benign_labels: str = (
        "Assumed benign baseline: unlabelled historical traffic is assumed benign rather than "
        "formally proven benign; ground truth derives exclusively from simulator ground truth "
        "or human-confirmed security incidents."
    )
    window_bounds: Dict[str, Any] = Field(
        description="Temporal and record count bounds of the evaluated replay window"
    )


class ReplayReport(BaseModel):
    """Complete evaluation report for a candidate policy denial rule."""

    candidate_rule: CandidateRule
    status: str = Field(description="ACCEPT | REJECT | INSUFFICIENT_EVIDENCE")
    coverage: float = Field(description="Proportion of attack events blocked (attacks_blocked / attacks_total)")
    attacks_total: int = Field(description="Total ATTACK records observed for the candidate agent")
    attacks_blocked: int = Field(description="ATTACK records for the candidate agent and tool that would be blocked")
    benign_total: int = Field(description="Total BENIGN_ASSUMED records observed for the candidate agent")
    benign_blocked: int = Field(description="BENIGN_ASSUMED records for the candidate agent and tool that would be blocked")
    false_block_point: float = Field(description="Empirical false block rate (benign_blocked / benign_total)")
    false_block_upper: float = Field(description="One-sided Clopper-Pearson statistical upper bound at 1 - delta")
    delta: float = Field(default=0.05, description="Significance level for the statistical upper bound (default 0.05 for 95% confidence)")
    assumptions: ReplayAssumptions

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serializes report to JSON."""
        return self.model_dump_json(indent=indent)


def compute_false_block_upper(benign_blocked: int, benign_total: int, delta: float = 0.05) -> float:
    """Computes the exact one-sided Clopper-Pearson upper bound for false blocks.
    
    Formula:
        BetaInv(1 - delta, benign_blocked + 1, benign_total - benign_blocked)
        where delta = 0.05 (for 95% one-sided confidence).
    """
    if benign_total <= 0:
        return 1.0
    if benign_blocked >= benign_total:
        return 1.0
    if benign_blocked < 0:
        raise ValueError(f"benign_blocked cannot be negative: {benign_blocked}")

    # Exact Clopper-Pearson one-sided upper bound via Beta PPF
    a = benign_blocked + 1
    b = benign_total - benign_blocked
    upper = float(beta_dist.ppf(1.0 - delta, a, b))
    return min(1.0, max(0.0, upper))


class ReplayEngine:
    """Pure, stateless counterfactual replay and statistical validation engine."""

    def __init__(self, delta: float = 0.05):
        self.delta = delta

    def evaluate(self, records: List[ActionRecord], candidate: CandidateRule) -> ReplayReport:
        """Evaluates a candidate deny rule against a sequence of ActionRecords."""
        # 1. Compute replay window bounds
        if records:
            start_ts = min(r.ts for r in records)
            end_ts = max(r.ts for r in records)
            duration_s = max(0.0, end_ts - start_ts)
        else:
            start_ts = 0.0
            end_ts = 0.0
            duration_s = 0.0

        window_bounds = {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "duration_seconds": duration_s,
            "records_evaluated": len(records),
        }

        # 2. Filter records for the candidate agent
        agent_records = [r for r in records if r.agent_id == candidate.agent_id]

        # 3. Compute Attack Metrics
        # attacks_total: ATTACK records for the agent
        attack_records = [r for r in agent_records if r.label == "ATTACK"]
        attacks_total = len(attack_records)

        # attacks_blocked: ATTACK records for the agent and candidate tool
        attacks_blocked_records = [
            r for r in attack_records
            if r.tool == candidate.tool and (candidate.mcp_id is None or r.mcp_id == candidate.mcp_id)
        ]
        attacks_blocked = len(attacks_blocked_records)
        coverage = (attacks_blocked / attacks_total) if attacks_total > 0 else 0.0

        # 4. Compute Benign Metrics
        # benign_total: BENIGN_ASSUMED records for the agent
        benign_records = [r for r in agent_records if r.label == "BENIGN_ASSUMED"]
        benign_total = len(benign_records)

        # benign_blocked: BENIGN_ASSUMED records for the agent and candidate tool
        benign_blocked_records = [
            r for r in benign_records
            if r.tool == candidate.tool and (candidate.mcp_id is None or r.mcp_id == candidate.mcp_id)
        ]
        benign_blocked = len(benign_blocked_records)
        false_block_point = (benign_blocked / benign_total) if benign_total > 0 else 0.0

        # 5. Compute Clopper-Pearson False-Block Upper Bound
        false_block_upper = compute_false_block_upper(benign_blocked, benign_total, delta=self.delta)

        # 6. Determine Status
        # Rules:
        # ACCEPT if coverage >= 0.90, false_block_upper <= 0.005, benign_total >= 600, and attacks_total >= 3.
        # INSUFFICIENT_EVIDENCE if a sample threshold fails.
        # REJECT if coverage or the bound fails with enough data.
        if benign_total < 600 or attacks_total < 3:
            status = "INSUFFICIENT_EVIDENCE"
        elif coverage >= 0.90 and false_block_upper <= 0.005:
            status = "ACCEPT"
        else:
            status = "REJECT"

        assumptions = ReplayAssumptions(window_bounds=window_bounds)

        return ReplayReport(
            candidate_rule=candidate,
            status=status,
            coverage=coverage,
            attacks_total=attacks_total,
            attacks_blocked=attacks_blocked,
            benign_total=benign_total,
            benign_blocked=benign_blocked,
            false_block_point=false_block_point,
            false_block_upper=false_block_upper,
            delta=self.delta,
            assumptions=assumptions,
        )


def evaluate_candidate_rule(
    records: List[ActionRecord],
    candidate: CandidateRule,
    delta: float = 0.05,
) -> ReplayReport:
    """Convenience functional interface for candidate rule evaluation."""
    engine = ReplayEngine(delta=delta)
    return engine.evaluate(records, candidate)
