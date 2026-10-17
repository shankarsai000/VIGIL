"""Mirage Synthetic Sandbox Database (Phase V2).

Provides realistic synthetic records for SHADOW_SANDBOX (Tier 2 honeypot containment).
Rule F compliant:
- Holds synthetic rows only, generated programmatically with explicit MIRAGE- markers.
- Never copies, ingests, or references real production or sandbox data.
- Isolated in-memory/file SQLite store strictly for shadowed sessions.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional


class MirageDatabase:
    """Synthetic honeypot database for shadowed sessions."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._access_log: List[Dict[str, Any]] = []
        self._records: List[Dict[str, Any]] = self._generate_synthetic_corpus()

    def _generate_synthetic_corpus(self) -> List[Dict[str, Any]]:
        """Generate purely synthetic records with deterministic pseudo-random attributes."""
        corpus = []
        company_names = [
            "Acme Synthetics Corp",
            "Mirage Logistics Global",
            "Phantom Energy Solutions",
            "Nebula Cloud Fabrications",
            "Honeynet Financial Services",
        ]
        
        for i, comp in enumerate(company_names):
            account_id = f"SYNTH-ACT-{1000 + i}"
            invoice_id = f"MIRAGE-INV-{8000 + i}"
            balance = round(15000.0 + (i * 3241.50) % 50000.0, 2)
            
            corpus.append({
                "account_id": account_id,
                "company_name": comp,
                "contact_email": f"billing@{comp.lower().replace(' ', '')}.mirage.internal",
                "invoice_id": invoice_id,
                "balance": balance,
                "credit_limit": 100000.0,
                "status": "ACTIVE_SYNTHETIC",
                "is_synthetic": True,
                "synthetic_tag": hashlib.sha256(f"{account_id}-{self.seed}".encode()).hexdigest()[:12],
            })
        return corpus

    def query(self, query_str: str, session_id: str = "unknown") -> Dict[str, Any]:
        """Execute query against synthetic honeypot data."""
        self._access_log.append({
            "timestamp": time.time(),
            "session_id": session_id,
            "query": query_str,
            "rows_served": len(self._records),
        })
        
        return {
            "source": "MIRAGE_SYNTHETIC_DATABASE",
            "session_id": session_id,
            "query": query_str,
            "rows_returned": len(self._records),
            "records": [dict(r) for r in self._records],
            "containment_notice": "SHADOW_ROUTED_SYNTHETIC_DATA",
        }

    @property
    def access_count(self) -> int:
        return len(self._access_log)

    def get_access_log(self) -> List[Dict[str, Any]]:
        return list(self._access_log)

    def verify_no_real_rows(self, real_records: List[Dict[str, Any]]) -> bool:
        """Prove zero intersection between synthetic records and provided real records."""
        synth_acc_ids = {r["account_id"] for r in self._records}
        real_acc_ids = {r.get("account_id") for r in real_records if "account_id" in r}
        return len(synth_acc_ids.intersection(real_acc_ids)) == 0


# Shared singleton instance for tools runtime
mirage_db = MirageDatabase()
