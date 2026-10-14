"""Incident-to-policy synthesis with replay validation.

Turns the tool calls seen in a confirmed attack into candidate ArmorIQ deny rules, then checks each candidate
against the same agent's benign history. A rule is proposed only if it blocks every attack call for that tool
and blocks zero benign calls by that agent. Otherwise the tool is rejected, with the reason recorded.

Proposals are never applied automatically. They come back as YAML for a reviewer, who adds them to the agent's
armoriq.yaml and registers it with the armoriq CLI.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List

TOOL_CALL = "TOOL_CALL"
_SAFE_TOOL = re.compile(r"[A-Za-z0-9_\-]{1,64}")


@dataclass(frozen=True)
class CallRecord:
    agent_id: str
    event_type: str
    target: str


@dataclass
class RuleProposal:
    agent_id: str
    deny: str
    attack_calls_blocked: int
    benign_calls_blocked: int
    notes: List[str] = field(default_factory=list)


@dataclass
class SynthesisReport:
    proposals: List[RuleProposal]
    skipped_non_tool_calls: int
    rejected: List[str]

    def to_yaml_patch(self) -> str:
        lines = ["# Proposed ArmorIQ deny rules. Review each one before running `armoriq register`.", ""]
        by_agent: Dict[str, List[str]] = {}
        for proposal in self.proposals:
            by_agent.setdefault(proposal.agent_id, []).append(proposal.deny)
        for agent_id, denies in sorted(by_agent.items()):
            lines.append(f"# config/{agent_id}.armoriq.yaml  ->  policy.deny")
            lines.append("policy:")
            lines.append("  deny:")
            lines.extend(f"    - {deny}" for deny in denies)
            lines.append("")
        return "\n".join(lines)


def synthesize(attack: Iterable[CallRecord], benign: Iterable[CallRecord], mcp_id: str) -> SynthesisReport:
    attack_calls = list(attack)
    benign_calls = list(benign)
    tool_attacks = [c for c in attack_calls if c.event_type == TOOL_CALL]
    skipped = len(attack_calls) - len(tool_attacks)
    proposals: List[RuleProposal] = []
    rejected: List[str] = []
    seen = set()

    for call in tool_attacks:
        key = (call.agent_id, call.target)
        if key in seen:
            continue
        seen.add(key)
        if not _SAFE_TOOL.fullmatch(call.target):
            rejected.append(f"{call.agent_id} -> {call.target!r}: not a plain tool name; refusing to write a glob from it")
            continue
        benign_hits = sum(
            1 for b in benign_calls
            if b.agent_id == call.agent_id and b.event_type == TOOL_CALL and b.target == call.target
        )
        if benign_hits:
            rejected.append(
                f"{call.agent_id} -> {call.target}: used legitimately {benign_hits} time(s); a rule would block real work"
            )
            continue
        attack_hits = sum(1 for a in tool_attacks if a.agent_id == call.agent_id and a.target == call.target)
        proposals.append(RuleProposal(
            agent_id=call.agent_id,
            deny=f"{mcp_id}.{call.target}",
            attack_calls_blocked=attack_hits,
            benign_calls_blocked=0,
            notes=["replay-validated: blocks every attack call for this tool, and 0 benign calls by this agent"],
        ))

    return SynthesisReport(proposals=proposals, skipped_non_tool_calls=skipped, rejected=rejected)
