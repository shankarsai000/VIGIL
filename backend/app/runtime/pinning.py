"""Tool Schema Pinning and Rug-Pull Detection (Phase V4).

Detects unauthorized modification of tool definitions (descriptions or parameter schemas)
post-registration. Computes canonical SHA-256 hashes stored in a tamper-evident hash-chained ledger.
On tool list refreshes, discrepancies flag tools as UNTRUSTED_SCHEMA and request an ArmorIQ hold/deny.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple


def compute_canonical_tool_hash(name: str, description: str, parameters: Dict[str, Any]) -> str:
    """Compute canonical deterministic SHA-256 over normalized tool metadata."""
    normalized = {
        "description": description.strip(),
        "name": name.strip(),
        "parameters": parameters,
    }
    canonical_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class PinningLedgerEntry:
    __slots__ = ("tool_id", "schema_hash", "prev_hash", "timestamp", "status", "entry_hash")

    def __init__(
        self,
        tool_id: str,
        schema_hash: str,
        prev_hash: str,
        timestamp: float,
        status: str = "TRUSTED_PINNED",
    ):
        self.tool_id = tool_id
        self.schema_hash = schema_hash
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.status = status
        self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = f"{self.tool_id}:{self.schema_hash}:{self.prev_hash}:{self.timestamp}:{self.status}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "schema_hash": self.schema_hash,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "status": self.status,
            "entry_hash": self.entry_hash,
        }


class ToolSchemaRegistry:
    """Hash-chained pinning registry for registered tools."""

    def __init__(self):
        self._pinned: Dict[str, str] = {}
        self._ledger: List[PinningLedgerEntry] = []
        self._untrusted_tools: Dict[str, Dict[str, Any]] = {}

    @property
    def last_hash(self) -> str:
        return self._ledger[-1].entry_hash if self._ledger else "GENESIS_0000000000000000"

    def register_tool(self, name: str, description: str, parameters: Dict[str, Any]) -> str:
        """Register tool canonical schema in the hash chain."""
        schema_hash = compute_canonical_tool_hash(name, description, parameters)
        entry = PinningLedgerEntry(
            tool_id=name,
            schema_hash=schema_hash,
            prev_hash=self.last_hash,
            timestamp=time.time(),
            status="TRUSTED_PINNED",
        )
        self._ledger.append(entry)
        self._pinned[name] = schema_hash
        return schema_hash

    def refresh_and_verify(
        self, name: str, description: str, parameters: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Verify refreshed tool schema against pinned hash.
        
        Returns (is_valid, error_reason).
        """
        if name not in self._pinned:
            # Unregistered tool
            return False, f"Tool '{name}' is not registered in pinning registry"

        current_hash = compute_canonical_tool_hash(name, description, parameters)
        pinned_hash = self._pinned[name]

        if current_hash != pinned_hash:
            reason = f"Tool '{name}' schema rug-pull detected: expected {pinned_hash[:12]}..., got {current_hash[:12]}..."
            entry = PinningLedgerEntry(
                tool_id=name,
                schema_hash=current_hash,
                prev_hash=self.last_hash,
                timestamp=time.time(),
                status="UNTRUSTED_SCHEMA",
            )
            self._ledger.append(entry)
            self._untrusted_tools[name] = {
                "detected_at": time.time(),
                "reason": reason,
                "current_hash": current_hash,
                "pinned_hash": pinned_hash,
            }
            return False, reason

        return True, None

    def is_tool_trusted(self, tool_id: str) -> bool:
        return tool_id in self._pinned and tool_id not in self._untrusted_tools

    def get_ledger(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._ledger]

    def verify_chain_integrity(self) -> bool:
        """Verify complete cryptographic continuity of the pinning hash chain."""
        for i in range(len(self._ledger)):
            entry = self._ledger[i]
            # Check self-hash
            if entry._compute_hash() != entry.entry_hash:
                return False
            # Check prev_hash
            expected_prev = "GENESIS_0000000000000000" if i == 0 else self._ledger[i - 1].entry_hash
            if entry.prev_hash != expected_prev:
                return False
        return True
