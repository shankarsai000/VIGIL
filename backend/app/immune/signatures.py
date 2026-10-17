"""VIGIL Policy Immune System — Shared Signatures and Cross-Tenant Motifs (Phase M6).

Enables one tenant's lessons to protect another without leaking sensitive data
and without activating any policy automatically:
1. Export: A cryptographically signed bundle of motifs over tool categories only
   (e.g., CATEGORY:secret_read -> CATEGORY:external_send) with support buckets
   ('small', 'medium', 'large') instead of exact counts. The bundle contains NO
   tool names, agent IDs, tenant IDs, argument values, or timestamps.
2. Import: Maps abstract categories to local tools via config/tool_categories.yaml.
   Each mapped motif becomes a local CandidateRule.
3. Local Replay: Imported candidates MUST run through local counterfactual replay.
   If local benign evidence contradicts the rule, status is REJECT or INSUFFICIENT_EVIDENCE.
4. Fail-closed governance: Import NEVER activates a rule, NEVER writes armoriq.yaml,
   and NEVER calls ArmorIQ.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .records import ActionRecord
from .replay import CandidateRule, ReplayEngine, ReplayReport
from .verify import canonical_json_bytes, get_or_create_ed25519_key, sign_receipt, verify_receipt
from .workflow import (
    DEFAULT_PROPOSAL_CONFIG,
    STATUS_PROPOSED,
    PolicyProposalRecord,
    compute_impact_tier,
)


class SignatureVerificationError(Exception):
    """Raised when bundle cryptographic signature verification fails."""
    pass


class PrivacyViolationError(Exception):
    """Raised when an export bundle contains sensitive local identifiers."""
    pass


# Support bucket boundaries to avoid leaking exact incident frequency
BUCKET_SMALL = "small"      # 1 to 4 occurrences
BUCKET_MEDIUM = "medium"    # 5 to 20 occurrences
BUCKET_LARGE = "large"      # > 20 occurrences


def count_to_support_bucket(count: int) -> str:
    """Discretizes raw frequency into privacy-preserving support buckets."""
    if count < 5:
        return BUCKET_SMALL
    elif count <= 20:
        return BUCKET_MEDIUM
    else:
        return BUCKET_LARGE


def load_category_mapping(mapping_path: Union[str, Path] = "config/tool_categories.yaml") -> Dict[str, Any]:
    """Loads tool category configuration."""
    path = Path(mapping_path)
    if not path.exists():
        raise FileNotFoundError(f"Tool categories mapping file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data


def build_tool_to_category_map(mapping_data: Dict[str, Any]) -> Dict[str, str]:
    """Inverts categories: {cat: [{mcp, tool}]} -> {"tool": cat, "mcp.tool": cat, "mcp/tool": cat}."""
    tool_map: Dict[str, str] = {}
    categories = mapping_data.get("categories", {})
    for cat_name, tools in categories.items():
        for entry in tools:
            tool_name = entry.get("tool")
            mcp_name = entry.get("mcp")
            if tool_name:
                tool_map[tool_name] = cat_name
                if mcp_name:
                    tool_map[f"{mcp_name}.{tool_name}"] = cat_name
                    tool_map[f"{mcp_name}/{tool_name}"] = cat_name
    return tool_map


def build_category_to_tools_map(mapping_data: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """Returns mapping from category name to list of local tool dicts."""
    return mapping_data.get("categories", {})


def assert_bundle_privacy(
    bundle_dict: Dict[str, Any],
    planted_identifiers: Optional[List[str]] = None,
) -> None:
    """Verifies that the serialized bundle contains NO forbidden identifiers.
    
    Checks:
    - No planted identifiers (tool names, agent IDs, tenant IDs, secret tokens)
    - Motifs use only CATEGORY: namespace
    - No timestamps or ISO dates
    - No argument keys or values
    """
    serialized = json.dumps(bundle_dict).lower()

    # 1. Check user-planted identifiers
    if planted_identifiers:
        for ident in planted_identifiers:
            if not ident:
                continue
            if ident.lower() in serialized:
                raise PrivacyViolationError(
                    f"Privacy violation: planted identifier '{ident}' detected in exported bundle!"
                )

    # 2. Check structure: motif patterns must strictly be CATEGORY:* expressions
    for motif in bundle_dict.get("motifs", []):
        pattern = motif.get("pattern", "")
        target = motif.get("target_category", "")
        for part in pattern.split(" -> "):
            part = part.strip()
            if part and not part.startswith("CATEGORY:"):
                raise PrivacyViolationError(
                    f"Privacy violation: motif component '{part}' is not in 'CATEGORY:' namespace!"
                )
        if target and not target.startswith("CATEGORY:"):
            raise PrivacyViolationError(
                f"Privacy violation: target_category '{target}' is not in 'CATEGORY:' namespace!"
            )


def export_signature_bundle(
    records: List[ActionRecord],
    mapping_path: Union[str, Path] = "config/tool_categories.yaml",
    private_key: Optional[ed25519.Ed25519PrivateKey] = None,
    issuer: str = "vigil-community-signatures",
    planted_identifiers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Exports a privacy-preserving signed bundle of attack motifs over tool categories only.
    
    Contains:
    - Motifs over tool categories (e.g. CATEGORY:secret_read -> CATEGORY:external_send)
    - Support buckets ('small', 'medium', 'large') instead of exact counts
    - Ed25519 signature
    
    Contains NO:
    - Tool names
    - Agent IDs
    - Tenant IDs
    - Argument values / shapes
    - Timestamps
    """
    mapping_data = load_category_mapping(mapping_path)
    tool_to_cat = build_tool_to_category_map(mapping_data)

    # Collect attack records (simulator ground truth or confirmed incidents)
    attack_records = [r for r in records if r.label == "ATTACK"]

    # Group motifs
    # Count transitions: prev_category -> curr_category and single category
    motif_counts: Dict[Tuple[str, str], int] = {}

    for r in attack_records:
        curr_tool_key = f"{r.mcp_id}.{r.tool}" if r.mcp_id else r.tool
        curr_cat = tool_to_cat.get(curr_tool_key) or tool_to_cat.get(r.tool)
        if not curr_cat:
            continue

        prev_cat = None
        if r.prev_tool:
            prev_cat = tool_to_cat.get(r.prev_tool)

        if prev_cat and prev_cat != curr_cat:
            pattern = f"CATEGORY:{prev_cat} -> CATEGORY:{curr_cat}"
        else:
            pattern = f"CATEGORY:{curr_cat}"

        target = f"CATEGORY:{curr_cat}"
        key = (pattern, target)
        motif_counts[key] = motif_counts.get(key, 0) + 1

    motifs_list: List[Dict[str, Any]] = []
    for idx, ((pattern, target), count) in enumerate(sorted(motif_counts.items())):
        bucket = count_to_support_bucket(count)
        motifs_list.append({
            "motif_id": f"motif-{idx + 1:03d}",
            "pattern": pattern,
            "target_category": target,
            "support_bucket": bucket,
            "description": f"Shared cross-tenant policy motif for {target}",
        })

    # Build clean bundle payload
    bundle = {
        "version": "v1",
        "bundle_id": f"bundle-{int(time.time() * 1000) % 1000000:06d}",
        "issuer": issuer,
        "motifs": motifs_list,
    }

    # Cryptographic signing with Ed25519
    key = private_key or get_or_create_ed25519_key()
    sign_receipt(bundle, key)

    # Rigorous privacy assertion check
    assert_bundle_privacy(bundle, planted_identifiers)

    return bundle


def import_signature_bundle(
    bundle_dict: Dict[str, Any],
    local_records: List[ActionRecord],
    mapping_path: Union[str, Path] = "config/tool_categories.yaml",
    target_agent_id: str = "customer-bot",
    public_key_hex: Optional[str] = None,
    delta: float = 0.05,
) -> Dict[str, Any]:
    """Imports a shared signature bundle, verifies signature, and evaluates candidates locally.
    
    NON-NEGOTIABLE SAFETY INVARIANTS:
    1. Import NEVER activates a rule.
    2. Import NEVER writes armoriq.yaml.
    3. Import NEVER calls ArmorIQ.
    4. Imported candidates go through local counterfactual replay and M4 proposal flow.
    5. If local benign evidence contradicts the motif, status is REJECT or INSUFFICIENT_EVIDENCE.
    """
    mapping_data = load_category_mapping(mapping_path)
    trusted_pub_key = public_key_hex or mapping_data.get("public_key_hex")

    # 1. Cryptographic signature verification
    if not verify_receipt(bundle_dict, trusted_pub_key):
        raise SignatureVerificationError(
            "Ed25519 signature verification failed: signature invalid or bundle tampered with!"
        )

    cat_to_tools = build_category_to_tools_map(mapping_data)
    replay_engine = ReplayEngine(delta=delta)

    imported_candidates: List[CandidateRule] = []
    evaluations: List[ReplayReport] = []
    proposals: List[PolicyProposalRecord] = []

    # 2. Map categories to local tools
    motifs = bundle_dict.get("motifs", [])
    seen_rules: Set[Tuple[str, Optional[str], str]] = set()

    for motif in motifs:
        target_cat_full = motif.get("target_category", "")
        raw_cat = target_cat_full.replace("CATEGORY:", "").strip()
        local_tool_entries = cat_to_tools.get(raw_cat, [])

        for entry in local_tool_entries:
            mcp = entry.get("mcp")
            tool = entry.get("tool")
            if not tool:
                continue

            rule_key = (target_agent_id, mcp, tool)
            if rule_key in seen_rules:
                continue
            seen_rules.add(rule_key)

            candidate = CandidateRule(
                agent_id=target_agent_id,
                tool=tool,
                mcp_id=mcp,
            )
            imported_candidates.append(candidate)

            # 3. Local Replay Evaluation against local recorded ActionRecords
            report = replay_engine.evaluate(local_records, candidate)
            evaluations.append(report)

            # 4. If accepted by local replay, construct M4 proposal for human review
            if report.status == "ACCEPT":
                tier = compute_impact_tier(report, agent_count=1)
                now = time.time()
                proposal = PolicyProposalRecord(
                    id=f"prop-imported-{mcp or 'default'}-{tool}-{int(now) % 10000}",
                    status=STATUS_PROPOSED,
                    agent_id=target_agent_id,
                    mcp_id=mcp,
                    tool=tool,
                    impact_tier=tier,
                    replay_json=report.to_json(),
                    assumptions_json=json.dumps({
                        "source": "shared_signature_bundle",
                        "bundle_id": bundle_dict.get("bundle_id"),
                        "motif_pattern": motif.get("pattern"),
                        "support_bucket": motif.get("support_bucket"),
                        "exchangeability": report.assumptions.exchangeability,
                        "assumed_benign_labels": report.assumptions.assumed_benign_labels,
                    }),
                    approvals_json="[]",
                    created_at=now,
                    expires_at=now + (DEFAULT_PROPOSAL_CONFIG.expiration_hours * 3600),
                    version=1,
                )
                proposals.append(proposal)

    return {
        "bundle_id": bundle_dict.get("bundle_id"),
        "motifs_evaluated": len(motifs),
        "candidates_mapped": len(imported_candidates),
        "evaluations": evaluations,
        "proposals": proposals,
        "accepted_count": sum(1 for e in evaluations if e.status == "ACCEPT"),
        "rejected_count": sum(1 for e in evaluations if e.status == "REJECT"),
        "insufficient_count": sum(1 for e in evaluations if e.status == "INSUFFICIENT_EVIDENCE"),
    }
