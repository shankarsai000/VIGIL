"""VIGIL Policy Immune System — ArmorIQ Policy Compiler and Dry-Run Engine.

Compiles accepted candidate security denial rules into:
1. armoriq.yaml patch (dot notation: <mcp>.<tool> under policy.deny, one file per agent)
2. SDK inline policy (slash notation: {"allow": [...], "deny": ["<mcp>/<tool>", ...]})
3. Execution manifest with proposal ID, ReplayReport, and exchangeability assumptions.

SAFETY & GOVERNANCE RULES:
- Dry-run by default. No filesystem writes unless --write is explicitly requested.
- --write strictly requires proposal status APPROVED and approval count >= tier demand.
- Reuses name-safety check from synthesis.py. Refuses any non-plain identifier.
- Idempotent: compiling twice gives byte-for-byte identical output.
"""

from __future__ import annotations

import argparse
from enum import Enum
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from .candidates import AttackFamilyCandidate, STATUS_ACCEPT
from .replay import CandidateRule, ReplayReport

# Reuse name-safety check from synthesis.py
SAFE_TOOL_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


class ImpactTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


IMPACT_TIER_REQUIRED_APPROVALS: Dict[ImpactTier, int] = {
    ImpactTier.LOW: 1,
    ImpactTier.MEDIUM: 1,
    ImpactTier.HIGH: 2,
    ImpactTier.CRITICAL: 2,
}

PROPOSAL_APPROVED = "APPROVED"
PROPOSAL_PENDING = "PENDING"
PROPOSAL_REJECTED = "REJECTED"


class ApprovalError(Exception):
    """Raised when --write is attempted without meeting governance approval demands."""


class PolicyProposal(BaseModel):
    """Governance proposal packaging candidate rules for agent policy compilation."""

    proposal_id: str
    agent_id: str
    status: str = PROPOSAL_PENDING
    impact_tier: ImpactTier = ImpactTier.LOW
    approvals: List[str] = Field(default_factory=list, description="List of approver keys/identities")
    candidates: List[AttackFamilyCandidate] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class CompiledArtifacts(BaseModel):
    """Byte-for-byte deterministic compiler output artifacts."""

    proposal_id: str
    agent_id: str
    yaml_patch_filename: str
    yaml_patch_content: str
    inline_policy: Dict[str, List[str]]
    manifest: Dict[str, Any]

    def yaml_bytes(self) -> bytes:
        return self.yaml_patch_content.encode("utf-8")

    def inline_policy_bytes(self) -> bytes:
        return json.dumps(self.inline_policy, indent=2, sort_keys=True).encode("utf-8")

    def manifest_bytes(self) -> bytes:
        return json.dumps(self.manifest, indent=2, sort_keys=True).encode("utf-8")


def validate_identifier(name: str, context: str) -> None:
    """Enforces that name is a plain identifier safe for glob generation."""
    if not SAFE_IDENTIFIER_PATTERN.fullmatch(name):
        raise ValueError(f"{context} '{name}' is not a plain identifier; refusing to compile rule from it")


def compile_agent_policy(
    proposal: PolicyProposal,
    default_mcp: str = "default-mcp",
) -> CompiledArtifacts:
    """Compiles ACCEPT candidate rules for an agent into deterministic ArmorIQ artifacts.
    
    Produces:
    a. armoriq.yaml patch in dot notation (<mcp>.<tool>) under policy.deny
    b. SDK inline policy in slash notation ({"allow": [], "deny": ["<mcp>/<tool>"]})
    c. Manifest containing proposal_id, replay reports, and statistical assumptions.
    """
    validate_identifier(proposal.agent_id, "Agent ID")

    # Filter for ACCEPT candidates only
    accepted = [c for c in proposal.candidates if c.status == STATUS_ACCEPT]

    # Validate tool identifiers and determine deny rules
    dot_denies: List[str] = []
    slash_denies: List[str] = []
    replay_reports: List[Dict[str, Any]] = []
    combined_assumptions: Dict[str, Any] = {}

    for cand in sorted(accepted, key=lambda c: (c.tool, c.mcp_id or "")):
        validate_identifier(cand.tool, "Tool name")
        mcp = cand.mcp_id or default_mcp
        validate_identifier(mcp, "MCP ID")

        dot_rule = f"{mcp}.{cand.tool}"
        slash_rule = f"{mcp}/{cand.tool}"

        if dot_rule not in dot_denies:
            dot_denies.append(dot_rule)
        if slash_rule not in slash_denies:
            slash_denies.append(slash_rule)

        if cand.replay_report:
            rep_dict = cand.replay_report.model_dump()
            replay_reports.append(rep_dict)
            if not combined_assumptions:
                combined_assumptions = rep_dict.get("assumptions", {})

    # a. armoriq.yaml patch in dot notation under policy.deny (one file per agent)
    # Formatted to conform to ArmorIQConfig syntax for armoriq validate
    yaml_lines = [
        f"# Proposed ArmorIQ deny rules for agent: {proposal.agent_id}",
        "# Compatible with ArmorIQ CLI: armoriq validate --config <file>",
        "version: v1",
        "identity:",
        "  api_key: ${ARMORIQ_API_KEY}",
        "  user_id: ${ARMORIQ_USER_EMAIL}",
        f"  agent_id: {proposal.agent_id}",
        "policy:",
        "  allow: []",
        "  deny:",
    ]
    if dot_denies:
        for r in dot_denies:
            yaml_lines.append(f"    - {r}")
    else:
        yaml_lines.append("    # (No active deny rules)")
    yaml_lines.append("")
    yaml_patch_content = "\n".join(yaml_lines)

    # b. SDK inline policy in slash notation
    inline_policy = {
        "allow": [],
        "deny": slash_denies,
    }

    # c. Manifest with proposal ID, replay report, and assumptions
    manifest = {
        "proposal_id": proposal.proposal_id,
        "agent_id": proposal.agent_id,
        "impact_tier": proposal.impact_tier.value,
        "status": proposal.status,
        "approval_count": len(proposal.approvals),
        "approvals": sorted(proposal.approvals),
        "rules_count": len(dot_denies),
        "replay_reports": replay_reports,
        "assumptions": combined_assumptions,
        "rules": {
            "dot_notation": dot_denies,
            "slash_notation": slash_denies,
        },
    }

    return CompiledArtifacts(
        proposal_id=proposal.proposal_id,
        agent_id=proposal.agent_id,
        yaml_patch_filename=f"{proposal.agent_id}.armoriq.yaml",
        yaml_patch_content=yaml_patch_content,
        inline_policy=inline_policy,
        manifest=manifest,
    )


def execute_compile(
    proposal: PolicyProposal,
    write: bool = False,
    output_dir: Optional[Path] = None,
    default_mcp: str = "default-mcp",
) -> Tuple[CompiledArtifacts, List[Path]]:
    """Executes compiler pipeline with strict dry-run enforcement and approval gate checks.
    
    Returns:
        Tuple of (CompiledArtifacts, list of written file Paths).
        In dry-run mode (write=False), the returned file list is always empty.
    """
    artifacts = compile_agent_policy(proposal, default_mcp=default_mcp)
    written_files: List[Path] = []

    if not write:
        # Dry-run default: write nothing to the filesystem
        return artifacts, written_files

    # Strict --write gate check
    if proposal.status != PROPOSAL_APPROVED:
        raise ApprovalError(
            f"Cannot write artifacts: proposal '{proposal.proposal_id}' status is "
            f"'{proposal.status}', but must be '{PROPOSAL_APPROVED}'."
        )

    required_approvals = IMPACT_TIER_REQUIRED_APPROVALS.get(proposal.impact_tier, 1)
    if len(proposal.approvals) < required_approvals:
        raise ApprovalError(
            f"Cannot write artifacts: proposal '{proposal.proposal_id}' has {len(proposal.approvals)} "
            f"approval(s), but impact tier '{proposal.impact_tier.value}' demands at least {required_approvals}."
        )

    target_dir = output_dir or Path("evidence/M3")
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write YAML patch file
    yaml_file = target_dir / artifacts.yaml_patch_filename
    yaml_file.write_bytes(artifacts.yaml_bytes())
    written_files.append(yaml_file)

    # 2. Write SDK inline policy JSON
    inline_file = target_dir / f"{proposal.agent_id}.inline_policy.json"
    inline_file.write_bytes(artifacts.inline_policy_bytes())
    written_files.append(inline_file)

    # 3. Write Manifest JSON
    manifest_file = target_dir / f"{proposal.agent_id}.manifest.json"
    manifest_file.write_bytes(artifacts.manifest_bytes())
    written_files.append(manifest_file)

    return artifacts, written_files


def main() -> int:
    """CLI entrypoint for the ArmorIQ dry-run compiler."""
    parser = argparse.ArgumentParser(description="VIGIL ArmorIQ Policy Dry-Run Compiler")
    parser.add_argument("--proposal-file", required=True, help="Path to proposal JSON file")
    parser.add_argument("--write", action="store_true", default=False, help="Write artifacts to disk (requires approved proposal)")
    parser.add_argument("--output-dir", default="evidence/M3", help="Output directory for generated artifacts")
    args = parser.parse_args()

    proposal_path = Path(args.proposal_file)
    if not proposal_path.exists():
        sys.stderr.write(f"Error: proposal file not found: {proposal_path}\n")
        return 1

    try:
        with open(proposal_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        proposal = PolicyProposal.model_validate(data)
    except Exception as e:
        sys.stderr.write(f"Error reading proposal: {e}\n")
        return 1

    try:
        artifacts, written = execute_compile(
            proposal=proposal,
            write=args.write,
            output_dir=Path(args.output_dir),
        )
        if args.write:
            print(f"[Compiler] Wrote {len(written)} artifact(s) to {args.output_dir}:")
            for f in written:
                print(f"  - {f}")
        else:
            print("[Compiler] Dry-run complete. 0 files written to disk.")
            print("[Compiler] Manifest preview:")
            print(json.dumps(artifacts.manifest, indent=2))
        return 0
    except ApprovalError as e:
        sys.stderr.write(f"Approval Error: {e}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"Compilation Error: {e}\n")
        return 3


if __name__ == "__main__":
    sys.exit(main())
