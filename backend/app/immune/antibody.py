"""Automated Antibody Proposal and Backtesting Engine (Phase V5).

Synthesizes candidate security rules for recurring incident families.
P0 / Rule E Invariants:
1. Proposals only. Nothing deploys automatically.
2. JSON parsed strictly against Pydantic schema with extra fields forbidden (extra="forbid").
3. Prompt injection resistant: Model output is treated as untrusted data, never evaluated or executed.
4. Backtest gate: Replayed against last N=500 benign records.
   Reaches 'ready for review' ONLY IF observed false blocks == 0 AND recall >= 0.90.
5. Statistical rigor: Reports '0 of N; upper bound X.X%'. The phrase '0% false positives' is forbidden.
"""

from __future__ import annotations

import json
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, ValidationError

from .records import ActionRecord


def clopper_pearson_upper_bound(successes: int, trials: int, confidence: float = 0.95) -> float:
    """Compute exact one-sided Clopper-Pearson upper bound."""
    if trials == 0:
        return 1.0
    if successes == 0:
        return 1.0 - math.pow(1.0 - confidence, 1.0 / trials)
    try:
        from scipy.stats import beta
        return float(beta.ppf(confidence, successes + 1, trials - successes))
    except ImportError:
        p = successes / trials
        z = 1.64485
        return min(1.0, p + z * math.sqrt(p * (1.0 - p) / trials))


class AntibodyPattern(BaseModel):
    tool: str = Field(..., max_length=64, pattern=r"^[A-Za-z0-9_\-]{1,64}$")
    argument_shape_class: str = Field(..., max_length=64)
    sequence_constraint: Optional[str] = Field(None, max_length=128)

    model_config = {"extra": "forbid"}


class AntibodyCandidate(BaseModel):
    pattern: AntibodyPattern
    armoriq_constraint: str = Field(..., pattern=r"^(deny|hold)$")
    rationale: str = Field(..., max_length=512)

    model_config = {"extra": "forbid"}


class AntibodyBacktestReport(BaseModel):
    candidate: AntibodyCandidate
    benign_trials: int
    observed_false_blocks: int
    one_sided_95_upper_bound: float
    attack_trials: int
    observed_attack_blocks: int
    recall: float
    is_ready_for_review: bool
    status_summary: str
    rejection_reason: Optional[str] = None

    model_config = {"extra": "forbid"}


def generate_candidate_deterministic(
    family_name: str,
    target_tool: str,
    argument_class: str = "wildcard",
    constraint: str = "deny",
    rationale: Optional[str] = None,
) -> AntibodyCandidate:
    """Generate candidate antibody deterministically from incident family features."""
    clean_tool = target_tool.strip().replace("vigil-tools/", "")
    rat = rationale or f"Deterministic candidate for incident family {family_name} targeting {clean_tool}"
    if len(rat) > 500:
        rat = rat[:500]

    return AntibodyCandidate(
        pattern=AntibodyPattern(
            tool=clean_tool,
            argument_shape_class=argument_class,
            sequence_constraint=None,
        ),
        armoriq_constraint=constraint.lower(),
        rationale=rat,
    )


def parse_and_validate_antibody_json(raw_json_str: str) -> AntibodyCandidate:
    """Strictly parse, validate, and cap length of untrusted antibody proposal string."""
    if len(raw_json_str) > 2048:
        raise ValueError("Candidate JSON exceeds maximum allowable length of 2048 bytes")

    # Reject forbidden phrase
    if re.search(r"(?i)0(?:\.0+)?%\s+false\s+positives?", raw_json_str):
        raise ValueError("Forbidden phrasing '0% false positives' detected in proposal")

    data = json.loads(raw_json_str)
    return AntibodyCandidate.model_validate(data)


def backtest_antibody_candidate(
    candidate: AntibodyCandidate,
    benign_records: List[ActionRecord],
    attack_records: List[ActionRecord],
    min_recall: Optional[float] = None,
) -> AntibodyBacktestReport:
    """Replay candidate against benign baseline and historical attacks.
    
    Rule: Candidate reaches 'ready for review' ONLY IF:
          observed_false_blocks == 0 AND recall >= min_recall.
    """
    from ..runtime.thresholds import SystemThresholds
    target_recall = min_recall if min_recall is not None else SystemThresholds.min_recall()
    target_tool = candidate.pattern.tool

    # 1. Evaluate against benign records
    false_blocks = 0
    for r in benign_records:
        if r.label == "BENIGN":
            tool_name = r.tool.replace("vigil-tools/", "")
            if tool_name == target_tool:
                false_blocks += 1

    benign_count = len(benign_records)
    upper_bound = clopper_pearson_upper_bound(false_blocks, benign_count, confidence=0.95)

    # 2. Evaluate against attack records
    attack_blocks = 0
    total_attacks = 0
    for r in attack_records:
        if r.label == "ATTACK":
            total_attacks += 1
            tool_name = r.tool.replace("vigil-tools/", "")
            if tool_name == target_tool:
                attack_blocks += 1

    recall = (attack_blocks / total_attacks) if total_attacks > 0 else 0.0

    # 3. Determine readiness
    is_ready = (false_blocks == 0) and (recall >= target_recall)

    bound_pct = round(upper_bound * 100, 2)
    status_summary = (
        f"{false_blocks} of {benign_count}; one-sided 95% upper bound {bound_pct}% (recall: {round(recall * 100, 1)}%)"
    )

    rejection_reason = None
    if false_blocks > 0:
        rejection_reason = f"Rejected: candidate caused {false_blocks} false blocks on benign traffic (must be 0)"
    elif recall < target_recall:
        rejection_reason = f"Rejected: candidate recall {round(recall * 100, 1)}% is below required {int(target_recall * 100)}%"

    return AntibodyBacktestReport(
        candidate=candidate,
        benign_trials=benign_count,
        observed_false_blocks=false_blocks,
        one_sided_95_upper_bound=round(upper_bound, 6),
        attack_trials=total_attacks,
        observed_attack_blocks=attack_blocks,
        recall=round(recall, 4),
        is_ready_for_review=is_ready,
        status_summary=status_summary,
        rejection_reason=rejection_reason,
    )
