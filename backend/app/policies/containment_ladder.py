"""Graduated Containment Ladder (Phase V2).

Replaces binary quarantine with a 4-tier graduated containment hierarchy:
- Tier 0: LOG_ONLY (audit trail only)
- Tier 1: DOWNGRADE_SCOPE (deny write/admin tools in intent token, retain safe read tools)
- Tier 2: SHADOW_SANDBOX (transparent redirect of data operations to synthetic Mirage database)
- Tier 3: QUARANTINE_ROLLBACK (full isolation and backward compensating transaction rollback)

All thresholds are loaded from config/thresholds.yaml (never hard-coded).
Tier selection is a pure function. Escalation within a session is strictly monotonic.
Human release requires operator credentials via the P0-1 release workflow.
"""

from __future__ import annotations

import enum
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


class ContainmentTier(str, enum.Enum):
    LOG_ONLY = "LOG_ONLY"
    DOWNGRADE_SCOPE = "DOWNGRADE_SCOPE"
    SHADOW_SANDBOX = "SHADOW_SANDBOX"
    QUARANTINE_ROLLBACK = "QUARANTINE_ROLLBACK"


# Tier numeric rankings for monotonic escalation
TIER_ORDER: Dict[ContainmentTier, int] = {
    ContainmentTier.LOG_ONLY: 0,
    ContainmentTier.DOWNGRADE_SCOPE: 1,
    ContainmentTier.SHADOW_SANDBOX: 2,
    ContainmentTier.QUARANTINE_ROLLBACK: 3,
}


def load_containment_thresholds(config_path: Optional[Path] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = Path(__file__).resolve().parent.parent.parent.parent / "config" / "thresholds.yaml"
    
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    ladder = data.get("containment_ladder", {})
    return {
        "log_only_ceiling": float(ladder.get("log_only_ceiling", {}).get("value", 0.45)),
        "downgrade_min": float(ladder.get("surgical_downgrade_range", {}).get("min", 0.45)),
        "downgrade_max": float(ladder.get("surgical_downgrade_range", {}).get("max", 0.75)),
        "shadow_min": float(ladder.get("mirage_honeypot_range", {}).get("min", 0.75)),
        "shadow_max": float(ladder.get("mirage_honeypot_range", {}).get("max", 0.90)),
        "quarantine_min": float(ladder.get("quarantine_rollback_threshold", {}).get("value", 0.90)),
    }


def select_containment_tier(
    score: float,
    criticality: str = "MEDIUM",
    canary_hit: bool = False,
    thresholds: Optional[Dict[str, Any]] = None,
) -> ContainmentTier:
    """Pure function selecting containment tier from score, criticality, and canary state.
    
    Rule: Critical agents NEVER receive LOG_ONLY.
    Rule: Canary hits immediately trigger QUARANTINE_ROLLBACK.
    """
    if canary_hit:
        return ContainmentTier.QUARANTINE_ROLLBACK
    
    thresh = thresholds or load_containment_thresholds()
    
    if score >= thresh["quarantine_min"]:
        return ContainmentTier.QUARANTINE_ROLLBACK
    elif score >= thresh["shadow_min"]:
        return ContainmentTier.SHADOW_SANDBOX
    elif score >= thresh["downgrade_min"]:
        return ContainmentTier.DOWNGRADE_SCOPE
    else:
        # Score below 0.45:
        # Critical agents must never receive LOG_ONLY -> elevated to DOWNGRADE_SCOPE
        if str(criticality).strip().upper() == "CRITICAL":
            return ContainmentTier.DOWNGRADE_SCOPE
        return ContainmentTier.LOG_ONLY


class SessionContainmentState:
    """Tracks state and history of containment for a specific session."""
    def __init__(self, session_id: str, initial_tier: ContainmentTier = ContainmentTier.LOG_ONLY):
        self.session_id = session_id
        self.current_tier = initial_tier
        self.ledger_entries: List[str] = []
        self.history: List[Dict[str, Any]] = [
            {
                "tier": initial_tier.value,
                "timestamp": time.time(),
                "reason": "initial_session_registration",
                "source": "system",
            }
        ]
        self.updated_at = time.time()


class SessionContainmentManager:
    """Singleton/In-memory store for session containment directives.
    
    Guarantees monotonic escalation within sessions.
    Down-tier transitions require explicit human operator release.
    """
    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        self._sessions: Dict[str, SessionContainmentState] = {}
        self.thresholds = thresholds or load_containment_thresholds()

    def get_or_create(self, session_id: str) -> SessionContainmentState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionContainmentState(session_id)
        return self._sessions[session_id]

    def get_tier(self, session_id: str) -> ContainmentTier:
        return self.get_or_create(session_id).current_tier

    def escalate_session(
        self,
        session_id: str,
        new_tier: ContainmentTier,
        reason: str,
        ledger_entry_id: Optional[str] = None,
        source: str = "containment_gate",
    ) -> ContainmentTier:
        """Monotonically escalate session tier. Tiers never automatically de-escalate."""
        state = self.get_or_create(session_id)
        current_rank = TIER_ORDER[state.current_tier]
        new_rank = TIER_ORDER[new_tier]

        if new_rank > current_rank:
            state.current_tier = new_tier
            state.updated_at = time.time()
            if ledger_entry_id:
                state.ledger_entries.append(ledger_entry_id)
            state.history.append({
                "tier": new_tier.value,
                "timestamp": state.updated_at,
                "reason": reason,
                "source": source,
                "ledger_entry_id": ledger_entry_id,
            })
        return state.current_tier

    def release_session(
        self,
        session_id: str,
        operator_id: str,
        reason: str,
        target_tier: ContainmentTier = ContainmentTier.LOG_ONLY,
    ) -> ContainmentTier:
        """Human operator release de-escalating session containment."""
        state = self.get_or_create(session_id)
        state.current_tier = target_tier
        state.updated_at = time.time()
        state.history.append({
            "tier": target_tier.value,
            "timestamp": state.updated_at,
            "reason": f"Operator release by {operator_id}: {reason}",
            "source": f"human:{operator_id}",
        })
        return state.current_tier

    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        state = self.get_or_create(session_id)
        return {
            "session_id": state.session_id,
            "tier": state.current_tier.value,
            "updated_at": state.updated_at,
            "ledger_entries": list(state.ledger_entries),
            "history": list(state.history),
        }
