"""Sandbox Data Store with Mutation and Compensation Handlers (Phase V6).

Provides live state storage for sandbox accounts and billing tables with explicit
support for pre-state hashing, state mutations, and transactional inversions.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


def hash_state(data: Dict[str, Any]) -> str:
    canon = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class SandboxDataStore:
    """In-memory sandbox store supporting state mutations and inverse compensations."""

    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {
            "ACC-1001": {
                "account_id": "ACC-1001",
                "customer_name": "Acme Widgets",
                "balance": 5000.0,
                "tier": "STANDARD",
                "status": "ACTIVE",
            },
            "ACC-1002": {
                "account_id": "ACC-1002",
                "customer_name": "Globex Corp",
                "balance": 12500.0,
                "tier": "PREMIUM",
                "status": "ACTIVE",
            },
        }
        self.billing_records: Dict[str, Dict[str, Any]] = {
            "INV-9001": {"invoice_id": "INV-9001", "account_id": "ACC-1001", "amount": 450.0},
        }
        self.external_emails_sent: List[Dict[str, Any]] = []

    def get_account_snapshot(self, account_id: str) -> Dict[str, Any]:
        if account_id not in self.accounts:
            raise KeyError(f"Account {account_id} not found")
        return copy.deepcopy(self.accounts[account_id])

    def mutate_customer_account(self, account_id: str, new_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Perform mutation on customer account."""
        if account_id not in self.accounts:
            raise KeyError(f"Account {account_id} not found")
        self.accounts[account_id].update(new_fields)
        return copy.deepcopy(self.accounts[account_id])

    def insert_billing_record(self, invoice_id: str, amount: float, account_id: str) -> Dict[str, Any]:
        """Insert new billing record."""
        rec = {"invoice_id": invoice_id, "account_id": account_id, "amount": amount}
        self.billing_records[invoice_id] = rec
        return copy.deepcopy(rec)

    def dispatch_email(self, to: str, body: str) -> Dict[str, Any]:
        """Irreversible external side-effect."""
        msg = {"to": to, "body": body, "timestamp": 123456789.0}
        self.external_emails_sent.append(msg)
        return msg

    def apply_compensation(
        self,
        inverse_tool: str,
        target_id: str,
        pre_state_data: Dict[str, Any],
    ) -> Tuple[bool, Dict[str, Any]]:
        """Apply compensating inverse action."""
        if inverse_tool == "revert_customer_account":
            if target_id not in self.accounts:
                return False, {}
            # Restore exact pre-state snapshot
            self.accounts[target_id] = copy.deepcopy(pre_state_data)
            return True, self.accounts[target_id]

        elif inverse_tool == "delete_billing_record":
            if target_id in self.billing_records:
                deleted = self.billing_records.pop(target_id)
                return True, deleted
            return False, {}

        return False, {}
