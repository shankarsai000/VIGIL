"""VIGIL Decentralized Information Flow Control (DIFC) & Lineage Engine (Phase V1).

Tracks multi-hop agent delegation provenance and taint propagation.
Computes taint-derived inline policies for ArmorIQ intent token minting.
CRITICAL INVARIANT: Only ArmorIQ decides tool blocks. This engine computes
policy inputs (deny lists and taint assertions) and passes them to ArmorIQ.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

import yaml
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class TaintLevel(IntEnum):
    """Monotonically ordered taint levels for data and delegation flows."""
    SYSTEM_TRUSTED = 0      # Internal system prompts, signed configs
    VERIFIED_INTERNAL = 1   # Clean, verified internal agent state
    USER_UNTRUSTED = 2      # Direct external user input / prompt
    EXTERNAL_UNTRUSTED = 3  # Unverified external MCP output, web scrape, email


TAINT_NAMES = {
    TaintLevel.SYSTEM_TRUSTED: "SYSTEM_TRUSTED",
    TaintLevel.VERIFIED_INTERNAL: "VERIFIED_INTERNAL",
    TaintLevel.USER_UNTRUSTED: "USER_UNTRUSTED",
    TaintLevel.EXTERNAL_UNTRUSTED: "EXTERNAL_UNTRUSTED",
}

STATUS_VALID = "VALID"
STATUS_DEGRADED = "DEGRADED"


class LineageRecord(BaseModel):
    """An immutable, append-only record of an agent delegation or input receipt."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    from_agent: Optional[str] = None
    to_agent: str
    taint: TaintLevel
    source_label: str
    ts: float = Field(default_factory=time.time)
    status: str = STATUS_VALID
    degraded_reason: Optional[str] = None
    signature: str = "UNSIGNED"

    model_config = {"extra": "ignore"}

    def canonical_bytes(self) -> bytes:
        data = {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "taint": int(self.taint),
            "source_label": self.source_label,
            "ts": self.ts,
            "status": self.status,
            "degraded_reason": self.degraded_reason,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")


class TraceLineage(BaseModel):
    """Aggregated lineage state for a specific operational execution trace."""
    trace_id: str
    current_taint: TaintLevel = TaintLevel.SYSTEM_TRUSTED
    spans: List[LineageRecord] = Field(default_factory=list)
    status: str = STATUS_VALID
    degraded_reason: Optional[str] = None
    taint_sources: List[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


def load_thresholds() -> Dict[str, Any]:
    thresh_file = REPO_ROOT / "config" / "thresholds.yaml"
    if thresh_file.exists():
        try:
            with open(thresh_file, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {}


def load_sinks() -> Dict[str, Any]:
    sinks_file = REPO_ROOT / "config" / "sinks.yaml"
    if sinks_file.exists():
        try:
            with open(sinks_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return data.get("restricted_sinks", {})
        except Exception:
            pass
    return {}


def sign_lineage_record(record: LineageRecord) -> str:
    """Signs the canonical lineage record with Ed25519 if private key is available."""
    key_paths = [
        Path.home() / ".vigil" / "receipt_ed25519.key",
        REPO_ROOT / "backend" / "storage" / "keys" / "receipt_ed25519.key",
    ]
    for key_path in key_paths:
        if key_path.exists():
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                key_bytes = key_path.read_bytes()
                private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
                sig = private_key.sign(record.canonical_bytes())
                return sig.hex()
            except Exception:
                pass
    return "UNSIGNED"


class ProvenanceTracker:
    """Thread-safe DIFC provenance tracking and delegation DAG manager."""

    def __init__(self, ledger_path: Optional[Path] = None):
        self.ledger_path = ledger_path or (REPO_ROOT / "backend" / "storage" / "audit_ledger.jsonl")
        self._traces: Dict[str, TraceLineage] = {}
        self.thresholds = load_thresholds()
        self.restricted_sinks = load_sinks()
        
        # Read max delegation depth from thresholds
        prov_conf = self.thresholds.get("provenance_and_lineage", {})
        self.max_depth = prov_conf.get("max_delegation_depth", {}).get("value", 6)

    def get_lineage(self, trace_id: str) -> Optional[TraceLineage]:
        return self._traces.get(trace_id)

    def record_input(
        self,
        trace_id: str,
        to_agent: str,
        input_taint: TaintLevel,
        source_label: str,
    ) -> LineageRecord:
        """Records initial external input or prompt entry into a trace."""
        span_id = f"span-{uuid4().hex[:8]}"
        record = LineageRecord(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None,
            from_agent=None,
            to_agent=to_agent,
            taint=input_taint,
            source_label=source_label,
            ts=time.time(),
            status=STATUS_VALID,
            signature="UNSIGNED",
        )
        record.signature = sign_lineage_record(record)

        lineage = self._traces.get(trace_id)
        if lineage is None:
            lineage = TraceLineage(
                trace_id=trace_id,
                current_taint=input_taint,
                spans=[record],
                status=STATUS_VALID,
                taint_sources=[source_label],
            )
        else:
            # Monotonic upward propagation
            if input_taint > lineage.current_taint:
                lineage.current_taint = input_taint
            if source_label not in lineage.taint_sources:
                lineage.taint_sources.append(source_label)
            lineage.spans.append(record)

        self._traces[trace_id] = lineage
        self._append_to_ledger(record)
        return record

    def propagate_delegation(
        self,
        trace_id: str,
        from_agent: str,
        to_agent: str,
        payload_taint: TaintLevel,
        source_label: str,
        parent_span_id: Optional[str] = None,
    ) -> LineageRecord:
        """Propagates a delegation from one agent to another with cycle and depth detection."""
        lineage = self._traces.get(trace_id)
        if lineage is None:
            # No prior lineage recorded; initiate with payload taint
            lineage = TraceLineage(trace_id=trace_id, current_taint=payload_taint)

        # Monotonic propagation: child taint is max of prior current taint and payload taint
        effective_taint = max(lineage.current_taint, payload_taint)

        span_id = f"span-{uuid4().hex[:8]}"
        record = LineageRecord(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            from_agent=from_agent,
            to_agent=to_agent,
            taint=effective_taint,
            source_label=source_label,
            ts=time.time(),
            status=STATUS_VALID,
            signature="UNSIGNED",
        )

        # Check for cycles using graph walk
        simulated_spans = list(lineage.spans) + [record]
        has_cycle, cycle_path = self._detect_cycle(simulated_spans)
        if has_cycle:
            record.status = STATUS_DEGRADED
            record.degraded_reason = f"Delegation cycle detected: {' -> '.join(cycle_path)}"
            lineage.status = STATUS_DEGRADED
            lineage.degraded_reason = record.degraded_reason

        # Check delegation depth
        depth = self._calculate_longest_depth(simulated_spans)
        if depth > self.max_depth:
            record.status = STATUS_DEGRADED
            record.degraded_reason = f"Delegation depth exceeded limit: {depth} > {self.max_depth}"
            lineage.status = STATUS_DEGRADED
            lineage.degraded_reason = record.degraded_reason

        record.signature = sign_lineage_record(record)

        # Update trace lineage
        lineage.current_taint = effective_taint
        if source_label not in lineage.taint_sources:
            lineage.taint_sources.append(source_label)
        lineage.spans.append(record)
        self._traces[trace_id] = lineage

        self._append_to_ledger(record)
        return record

    def derive_mint_policy(
        self,
        trace_id: str,
        target_tool: str,
        target_mcp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Derives an inline policy dictionary to supply to ArmorIQ get_intent_token.
        
        FAIL-CLOSED INVARIANTS:
        1. If lineage is missing -> deny all restricted sinks.
        2. If lineage is DEGRADED (cycle or depth exceeded) -> deny all restricted sinks.
        3. If current_taint > sink_ceiling -> deny target tool.
        4. Else -> allow target tool.
        """
        sink_meta = self.restricted_sinks.get(target_tool)
        mcp_id = target_mcp or (sink_meta.get("mcp_id", "vigil-tools") if sink_meta else "vigil-tools")
        tool_glob = f"{mcp_id}/{target_tool}"

        # 1. Missing lineage (fail-closed)
        lineage = self.get_lineage(trace_id)
        if lineage is None:
            return {
                "allow": [],
                "deny": [f"{sink_meta.get('mcp_id', 'vigil-tools')}/{tool}" for tool, sink_meta in self.restricted_sinks.items()],
                "reason": "Missing lineage trace record (Fail-Closed)",
                "taint_level": "UNKNOWN",
                "enforcement_status": "DENY_MINT_POLICY",
            }

        # 2. Degraded lineage (cycle or depth overflow)
        if lineage.status == STATUS_DEGRADED:
            return {
                "allow": [],
                "deny": [tool_glob],
                "reason": lineage.degraded_reason or "Lineage degraded (Fail-Closed)",
                "taint_level": TAINT_NAMES.get(lineage.current_taint, "UNKNOWN"),
                "enforcement_status": "DENY_MINT_POLICY",
            }

        # 3. Privileged sink check
        if sink_meta:
            ceiling_str = sink_meta.get("ceiling", "SYSTEM_TRUSTED")
            ceiling_level = getattr(TaintLevel, ceiling_str, TaintLevel.SYSTEM_TRUSTED)
            if lineage.current_taint > ceiling_level:
                return {
                    "allow": [],
                    "deny": [tool_glob],
                    "reason": f"DIFC taint violation: tool '{target_tool}' requires taint <= {ceiling_str}, but trace carries {TAINT_NAMES[lineage.current_taint]}",
                    "taint_level": TAINT_NAMES[lineage.current_taint],
                    "enforcement_status": "DENY_MINT_POLICY",
                }

        # 4. Allowed under policy
        return {
            "allow": [tool_glob],
            "deny": [],
            "reason": "Lineage verified within permissible taint ceiling",
            "taint_level": TAINT_NAMES[lineage.current_taint],
            "enforcement_status": "ALLOW_MINT_POLICY",
        }

    def _detect_cycle(self, spans: List[LineageRecord]) -> Tuple[bool, List[str]]:
        """Walks the delegation graph using DFS to detect cycles."""
        adj: Dict[str, List[str]] = {}
        for s in spans:
            if s.from_agent and s.to_agent:
                adj.setdefault(s.from_agent, []).append(s.to_agent)

        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        path: List[str] = []

        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    path.append(neighbor)
                    return True
            rec_stack.remove(node)
            path.pop()
            return False

        for node in list(adj.keys()):
            if node not in visited:
                if dfs(node):
                    return True, path
        return False, []

    def _calculate_longest_depth(self, spans: List[LineageRecord]) -> int:
        """Calculates the longest chain length in delegation spans."""
        adj: Dict[str, List[str]] = {}
        all_nodes: Set[str] = set()
        in_degrees: Dict[str, int] = {}
        for s in spans:
            if s.from_agent and s.to_agent:
                adj.setdefault(s.from_agent, []).append(s.to_agent)
                all_nodes.add(s.from_agent)
                all_nodes.add(s.to_agent)
                in_degrees[s.to_agent] = in_degrees.get(s.to_agent, 0) + 1
                in_degrees.setdefault(s.from_agent, 0)

        if not adj:
            return len(spans)

        memo: Dict[str, int] = {}

        def get_depth(node: str, seen: Set[str]) -> int:
            if node in memo:
                return memo[node]
            if node in seen:
                return 0  # Cycle handled elsewhere
            max_d = 0
            for neighbor in adj.get(node, []):
                max_d = max(max_d, 1 + get_depth(neighbor, seen | {node}))
            memo[node] = max_d
            return max_d

        max_total = 0
        roots = [n for n in all_nodes if in_degrees.get(n, 0) == 0] or list(all_nodes)
        for r in roots:
            max_total = max(max_total, get_depth(r, set()))
        return max_total

    def _append_to_ledger(self, record: LineageRecord) -> None:
        """Appends a tamper-evident entry to the audit ledger file."""
        try:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "event_type": "LINEAGE_SPAN",
                "trace_id": record.trace_id,
                "span_id": record.span_id,
                "from_agent": record.from_agent,
                "to_agent": record.to_agent,
                "taint": int(record.taint),
                "taint_name": TAINT_NAMES.get(record.taint, "UNKNOWN"),
                "source_label": record.source_label,
                "status": record.status,
                "signature": record.signature,
                "ts": record.ts,
            }
            with open(self.ledger_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass
