"""Canary Tripwire and Synthetic Token Table (Phase V3).

Deploys HMAC-derived decoy tokens in dedicated sandbox canary tables.
Legitimate workflows NEVER query the canary table.
Tripwire conditions:
1. Direct read or query targeting canary tables.
2. Outbound tool arguments containing an active canary token.

Any canary tripwire trigger immediately escalates containment to QUARANTINE_ROLLBACK.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any, Dict, List, Optional, Set

from ..policies.containment_ladder import ContainmentTier


class CanaryToken:
    __slots__ = ("token_id", "secret_value", "table_name", "created_at")

    def __init__(self, token_id: str, secret_value: str, table_name: str, created_at: float):
        self.token_id = token_id
        self.secret_value = secret_value
        self.table_name = table_name
        self.created_at = created_at


class CanaryManager:
    """Manages active canary tokens and inspects queries/payloads for tripwire triggers."""

    CANARY_TABLE_NAMES = {
        "sandbox_canary_credentials",
        "mock_executive_tokens",
        "synthetic_payment_gateways",
    }

    def __init__(self, hmac_key: Optional[bytes] = None):
        self._key = hmac_key or os.getenv("CANARY_HMAC_SECRET", "vigil-canary-secret-2026").encode()
        self._active_tokens: Dict[str, CanaryToken] = {}
        self._token_strings: Set[str] = set()
        self._generate_default_canaries()

    def _derive_token(self, identifier: str) -> str:
        """Derive cryptographic HMAC token string for canary."""
        h = hmac.new(self._key, identifier.encode(), hashlib.sha256).hexdigest()
        return f"CANARY_SECRET_{h[:24]}"

    def _generate_default_canaries(self) -> None:
        """Populate synthetic canary rows across designated canary tables."""
        for tbl in self.CANARY_TABLE_NAMES:
            for idx in range(3):
                token_id = f"{tbl}_token_{idx}"
                secret_str = self._derive_token(f"{tbl}_{idx}_{int(time.time())}")
                canary = CanaryToken(
                    token_id=token_id,
                    secret_value=secret_str,
                    table_name=tbl,
                    created_at=time.time(),
                )
                self._active_tokens[token_id] = canary
                self._token_strings.add(secret_str)

    def get_canary_table_rows(self, table_name: str) -> List[Dict[str, Any]]:
        """Return decoy canary rows if canary table is queried."""
        return [
            {
                "canary_id": c.token_id,
                "table": c.table_name,
                "canary_token": c.secret_value,
                "created_at": c.created_at,
                "notice": "SYNTHETIC_CANARY_DO_NOT_EXFILTRATE",
            }
            for c in self._active_tokens.values()
            if c.table_name == table_name
        ]

    def check_query_or_payload(self, text_or_query: str) -> Optional[Dict[str, Any]]:
        """Inspect SQL queries or outbound tool parameters for canary tripwire breaches.
        
        Returns breach details if tripped, or None if clean.
        """
        lowered = text_or_query.lower()

        # 1. Check for query targeting canary table
        for tbl in self.CANARY_TABLE_NAMES:
            if tbl in lowered:
                return {
                    "tripped": True,
                    "trigger_type": "CANARY_TABLE_ACCESS",
                    "target_table": tbl,
                    "recommended_tier": ContainmentTier.QUARANTINE_ROLLBACK.value,
                    "timestamp": time.time(),
                }

        # 2. Check for token exfiltration in outbound tool call arguments
        for token_str in self._token_strings:
            if token_str in text_or_query:
                return {
                    "tripped": True,
                    "trigger_type": "CANARY_TOKEN_EXFILTRATION",
                    "canary_token_prefix": token_str[:16] + "...",
                    "recommended_tier": ContainmentTier.QUARANTINE_ROLLBACK.value,
                    "timestamp": time.time(),
                }

        return None


# Global singleton instance
canary_tripwire = CanaryManager()
CanaryTripwire = CanaryManager
