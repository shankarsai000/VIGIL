"""VIGIL Policy Immune System — Candidate Rule Extraction and Triage.

Transforms observed attack families into candidate security denial rules
and performs counterfactual replay triage.

Classifications:
- ACCEPT: Replay verified with coverage >= 0.90, false_block_upper <= 0.005,
  benign_total >= 600, and attacks_total >= 3.
- INSUFFICIENT_EVIDENCE: Replay evaluation has insufficient samples (<600 benign or <3 attacks).
- REJECT: Replay evaluation fails coverage (<0.90) or statistical bound (>0.005).
- NOT_ENFORCEABLE: The attack family and benign traffic share the same tool name
  and separate only by argument values. Since ArmorIQ globs match tools and not
  argument values, a tool-level glob cannot safely block the attack without
  blocking benign operations.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from .records import ActionRecord
from .replay import CandidateRule, ReplayReport, evaluate_candidate_rule

# Reuse name-safety check from synthesis.py
SAFE_TOOL_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

STATUS_ACCEPT = "ACCEPT"
STATUS_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
STATUS_REJECT = "REJECT"
STATUS_NOT_ENFORCEABLE = "NOT_ENFORCEABLE"


class AttackFamilyCandidate(BaseModel):
    """A synthesized candidate denial rule evaluated against historical replay."""

    agent_id: str
    tool: str
    mcp_id: Optional[str] = None
    status: str = Field(description="ACCEPT | INSUFFICIENT_EVIDENCE | REJECT | NOT_ENFORCEABLE")
    reason: str = Field(description="Operational rationale for the status determination")
    replay_report: Optional[ReplayReport] = None
    candidate_rule: CandidateRule

    model_config = {"extra": "ignore"}


def extract_candidates(
    records: Iterable[ActionRecord],
    delta: float = 0.05,
    arg_separated_families: Optional[Set[Tuple[str, str]]] = None,
) -> List[AttackFamilyCandidate]:
    """Groups ATTACK records by (agent_id, tool) and evaluates each family through replay.
    
    Args:
        records: Historical stream of ActionRecord items.
        delta: Significance level for Clopper-Pearson bound (default 0.05).
        arg_separated_families: Optional set of (agent_id, tool) explicitly known to separate
                                only by argument value.
    
    Returns:
        List of AttackFamilyCandidate objects sorted deterministically by (agent_id, tool).
    """
    records_list = list(records)
    attack_records = [r for r in records_list if r.label == "ATTACK"]
    arg_separated = arg_separated_families or set()

    # Group attacks by (agent_id, tool)
    groups: Dict[Tuple[str, str], List[ActionRecord]] = {}
    for r in attack_records:
        groups.setdefault((r.agent_id, r.tool), []).append(r)

    candidates: List[AttackFamilyCandidate] = []

    for (agent_id, tool), att_recs in sorted(groups.items()):
        # Determine predominant mcp_id for this tool invocation
        mcp_id = att_recs[0].mcp_id if att_recs else None
        candidate = CandidateRule(agent_id=agent_id, tool=tool, mcp_id=mcp_id)

        # 1. Tool name safety check (must be a plain identifier)
        if not SAFE_TOOL_PATTERN.fullmatch(tool):
            candidates.append(
                AttackFamilyCandidate(
                    agent_id=agent_id,
                    tool=tool,
                    mcp_id=mcp_id,
                    status=STATUS_REJECT,
                    reason=f"{agent_id} -> {tool!r}: not a plain tool name; refusing to write a glob from it",
                    replay_report=None,
                    candidate_rule=candidate,
                )
            )
            continue

        # 2. Evaluate candidate rule via pure replay engine
        report = evaluate_candidate_rule(records_list, candidate, delta=delta)

        # 3. Check if family separates only by argument value
        # In ArmorIQ, policy rules match tools (<mcp>.<tool>), not argument values.
        # If the tool is legitimately used in benign traffic (benign_blocked > 0)
        # or declared arg-separated, any attempt to separate attacks requires
        # inspecting argument values.
        if report.benign_blocked > 0 or (agent_id, tool) in arg_separated:
            candidates.append(
                AttackFamilyCandidate(
                    agent_id=agent_id,
                    tool=tool,
                    mcp_id=mcp_id,
                    status=STATUS_NOT_ENFORCEABLE,
                    reason=(
                        f"Separates only by argument value: tool '{tool}' is invoked legitimately in "
                        f"{report.benign_blocked} benign record(s) for agent '{agent_id}'. "
                        "ArmorIQ globs match tools, not argument values."
                    ),
                    replay_report=report,
                    candidate_rule=candidate,
                )
            )
            continue

        # 4. Standard Replay Engine outcomes
        if report.status == STATUS_ACCEPT:
            candidates.append(
                AttackFamilyCandidate(
                    agent_id=agent_id,
                    tool=tool,
                    mcp_id=mcp_id,
                    status=STATUS_ACCEPT,
                    reason=(
                        f"Replay verified: coverage={report.coverage:.2f}, "
                        f"false_block_upper={report.false_block_upper:.6f} <= 0.005 "
                        f"(benign_total={report.benign_total}, attacks_total={report.attacks_total})"
                    ),
                    replay_report=report,
                    candidate_rule=candidate,
                )
            )
        elif report.status == STATUS_INSUFFICIENT_EVIDENCE:
            candidates.append(
                AttackFamilyCandidate(
                    agent_id=agent_id,
                    tool=tool,
                    mcp_id=mcp_id,
                    status=STATUS_INSUFFICIENT_EVIDENCE,
                    reason=(
                        f"Insufficient evidence for statistical bound: benign_total={report.benign_total} "
                        f"(req >= 600), attacks_total={report.attacks_total} (req >= 3)"
                    ),
                    replay_report=report,
                    candidate_rule=candidate,
                )
            )
        else:
            candidates.append(
                AttackFamilyCandidate(
                    agent_id=agent_id,
                    tool=tool,
                    mcp_id=mcp_id,
                    status=STATUS_REJECT,
                    reason=(
                        f"Replay rejected: coverage={report.coverage:.2f} (req >= 0.90) or "
                        f"false_block_upper={report.false_block_upper:.6f} > 0.005"
                    ),
                    replay_report=report,
                    candidate_rule=candidate,
                )
            )

    return candidates
