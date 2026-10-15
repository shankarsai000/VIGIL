"""VIGIL Policy Immune System — Action Record & Redaction Schema v1.

Every observed agent action becomes a redacted, structural record.
Raw argument values and payload contents are NEVER stored.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


def _compute_hmac(value: Any, key: Optional[str]) -> Optional[str]:
    """Computes HMAC-SHA256 digest of a scalar representation if key is configured."""
    if not key:
        return None
    val_str = str(value)
    return hmac.new(key.encode("utf-8"), val_str.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_arg_shape(payload: Any, hmac_key: Optional[str] = None) -> Dict[str, Any]:
    """Extracts a redacted structural shape from an argument or payload.
    
    Guarantees:
    - Retains ONLY data types, character lengths, and dictionary key names.
    - Raw strings, numbers, and secrets are strictly discarded.
    - If hmac_key (or TRACE_VALUE_HMAC_KEY env var) is set, stores an HMAC digest of the value.
    - If hmac_key is not set, no value hash is stored.
    """
    if hmac_key is None:
        hmac_key = os.getenv("TRACE_VALUE_HMAC_KEY") or None

    if payload is None:
        return {"type": "NoneType"}

    if isinstance(payload, str):
        trimmed = payload.strip()
        # Parse nested JSON structures if present
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                parsed = json.loads(trimmed)
                return compute_arg_shape(parsed, hmac_key=hmac_key)
            except Exception:
                pass

        res: Dict[str, Any] = {
            "type": "str",
            "len": len(payload),
        }
        digest = _compute_hmac(payload, hmac_key)
        if digest:
            res["hmac"] = digest
        return res

    elif isinstance(payload, dict):
        res = {"type": "dict", "keys": {}}
        for k, v in payload.items():
            res["keys"][str(k)] = compute_arg_shape(v, hmac_key=hmac_key)
        return res

    elif isinstance(payload, (list, tuple, set)):
        items = list(payload)
        res = {
            "type": "list",
            "len": len(items),
            "items": [compute_arg_shape(item, hmac_key=hmac_key) for item in items[:50]],
        }
        return res

    elif isinstance(payload, bool):
        res = {"type": "bool"}
        digest = _compute_hmac(payload, hmac_key)
        if digest:
            res["hmac"] = digest
        return res

    elif isinstance(payload, (int, float)):
        res = {"type": type(payload).__name__}
        digest = _compute_hmac(payload, hmac_key)
        if digest:
            res["hmac"] = digest
        return res

    else:
        res = {"type": type(payload).__name__}
        digest = _compute_hmac(payload, hmac_key)
        if digest:
            res["hmac"] = digest
        return res


class ActionRecord(BaseModel):
    """Schema v1 of a redacted, tamper-evident action trace record."""

    record_id: str = Field(default_factory=lambda: str(uuid4()))
    trace_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str = Field(default="default")
    agent_id: str
    ts: float = Field(default_factory=time.time)
    mcp_id: Optional[str] = None
    tool: Optional[str] = None
    event_type: str
    arg_shape: Dict[str, Any]
    provenance: str = Field(default="unknown")  # trusted | untrusted_content | unknown
    prev_tool: Optional[str] = None
    observed_decision: str = Field(default="ALLOW")  # ALLOW | DENY | HOLD | UNOBSERVED
    label: str = Field(default="BENIGN_ASSUMED")  # ATTACK | BENIGN_ASSUMED | UNLABELLED
    label_source: str = Field(default="none")  # simulator_ground_truth | incident_confirmed | none
    incident_id: Optional[str] = None

    model_config = {
        "extra": "ignore"
    }

    @classmethod
    def from_agent_event(
        cls,
        event: Any,
        observed_decision: str = "ALLOW",
        prev_tool: Optional[str] = None,
        incident_id: Optional[str] = None,
        is_simulation_mode: bool = False,
        hmac_key: Optional[str] = None,
    ) -> ActionRecord:
        """Constructs an ActionRecord from an incoming AgentEvent with fail-closed label rules."""
        # 1. Structural Redaction
        raw_payload = getattr(event, "payload", "")
        shape = compute_arg_shape(raw_payload, hmac_key=hmac_key)

        # 2. Provenance
        origin = getattr(event, "origin", None)
        if origin == "simulator":
            provenance = "trusted"
        elif getattr(event, "untrusted_content", False):
            provenance = "untrusted_content"
        else:
            provenance = "unknown"

        # 3. Label & Label Source (Standing rule 3: Detector score NEVER sets a label)
        # Ground truth comes from simulator labels or human-confirmed incidents only.
        attack_type = getattr(event, "attack_type", None)
        if is_simulation_mode and origin == "simulator":
            label_source = "simulator_ground_truth"
            label = "ATTACK" if attack_type else "BENIGN_ASSUMED"
        else:
            label = "BENIGN_ASSUMED"
            label_source = "none"

        # 4. Tool & MCP mapping
        tool = getattr(event, "target", None)
        event_type_val = getattr(event.event_type, "value", str(event.event_type)) if hasattr(event, "event_type") else "TOOL_CALL"
        mcp_id = getattr(event, "mcp_id", None)
        tenant_id = getattr(event, "tenant_id", "default")
        trace_id = getattr(event, "trace_id", None) or str(uuid4())

        return cls(
            record_id=str(uuid4()),
            trace_id=trace_id,
            tenant_id=tenant_id,
            agent_id=event.agent_id,
            ts=getattr(event, "timestamp", time.time()),
            mcp_id=mcp_id,
            tool=tool,
            event_type=event_type_val,
            arg_shape=shape,
            provenance=provenance,
            prev_tool=prev_tool,
            observed_decision=observed_decision,
            label=label,
            label_source=label_source,
            incident_id=incident_id,
        )
