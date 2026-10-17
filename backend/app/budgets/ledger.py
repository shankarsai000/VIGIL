"""Sliding Window Exfiltration Budget Ledger (Phase V3).

Detects low-and-slow exfiltration that stays below single-request anomaly thresholds.
Tracks per-principal and per-trace aggregates across:
- 1-minute sliding window (10 KB ceiling)
- 1-hour sliding window (100 KB ceiling)
- Full session lifetime

Privacy/Compliance Invariant:
PERSIST AGGREGATES ONLY. Raw payload content is NEVER stored in memory records or disk logs.
"""

from __future__ import annotations

import collections
import json
import math
from pathlib import Path
import time
from typing import Any, Deque, Dict, List, Optional, Tuple
import yaml

from ..policies.containment_ladder import ContainmentTier


def compute_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (range 0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class BudgetWindowEntry:
    """Timestamped aggregate metrics entry. NEVER contains raw content."""
    __slots__ = ("timestamp", "byte_count", "record_count", "sensitive_record_count", "entropy")

    def __init__(
        self,
        timestamp: float,
        byte_count: int,
        record_count: int,
        sensitive_record_count: int,
        entropy: float,
    ):
        self.timestamp = timestamp
        self.byte_count = byte_count
        self.record_count = record_count
        self.sensitive_record_count = sensitive_record_count
        self.entropy = entropy

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "byte_count": self.byte_count,
            "record_count": self.record_count,
            "sensitive_record_count": self.sensitive_record_count,
            "entropy": self.entropy,
        }


class SlidingWindowBudget:
    """Sliding window state for a single principal or trace."""

    def __init__(self, key: str):
        self.key = key
        self.entries: Deque[BudgetWindowEntry] = collections.deque()
        self.session_total_bytes: int = 0
        self.session_total_records: int = 0
        self.session_sensitive_records: int = 0

    def prune(self, current_time: float, max_window_seconds: float = 3600.0) -> None:
        """Evict events older than 1 hour."""
        cutoff = current_time - max_window_seconds
        while self.entries and self.entries[0].timestamp < cutoff:
            self.entries.popleft()

    def record(
        self,
        current_time: float,
        byte_count: int,
        record_count: int,
        sensitive_record_count: int,
        entropy: float,
    ) -> None:
        self.session_total_bytes += byte_count
        self.session_total_records += record_count
        self.session_sensitive_records += sensitive_record_count
        self.entries.append(
            BudgetWindowEntry(
                timestamp=current_time,
                byte_count=byte_count,
                record_count=record_count,
                sensitive_record_count=sensitive_record_count,
                entropy=entropy,
            )
        )
        self.prune(current_time)

    def get_window_sum(self, current_time: float, window_seconds: float) -> Tuple[int, int, int, float]:
        """Returns (bytes, records, sensitive_records, avg_entropy) over window."""
        cutoff = current_time - window_seconds
        total_bytes = 0
        total_records = 0
        total_sensitive = 0
        weighted_entropy_sum = 0.0

        for e in self.entries:
            if e.timestamp >= cutoff:
                total_bytes += e.byte_count
                total_records += e.record_count
                total_sensitive += e.sensitive_record_count
                weighted_entropy_sum += e.entropy * e.byte_count

        avg_entropy = (weighted_entropy_sum / total_bytes) if total_bytes > 0 else 0.0
        return total_bytes, total_records, total_sensitive, round(avg_entropy, 4)


class BudgetLedger:
    """Central ledger monitoring sliding window budgets across agents and traces."""

    def __init__(self, thresholds_path: Optional[Path] = None, ledger_file: Optional[Path] = None):
        self.thresholds = self._load_thresholds(thresholds_path)
        self.ledger_file = ledger_file
        self._principal_budgets: Dict[str, SlidingWindowBudget] = {}
        self._trace_budgets: Dict[str, SlidingWindowBudget] = {}

    def _load_thresholds(self, path: Optional[Path]) -> Dict[str, Any]:
        if path is None:
            path = Path(__file__).resolve().parent.parent.parent.parent / "config" / "thresholds.yaml"
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        b = data.get("low_and_slow_budgets", {})
        return {
            "window_1m_bytes_max": int(b.get("window_1m_bytes_max", {}).get("value", 10240)),
            "window_1h_bytes_max": int(b.get("window_1h_bytes_max", {}).get("value", 102400)),
            "shannon_entropy_threshold": float(b.get("shannon_entropy_threshold", {}).get("value", 5.8)),
        }

    def _get_principal_budget(self, agent_id: str) -> SlidingWindowBudget:
        if agent_id not in self._principal_budgets:
            self._principal_budgets[agent_id] = SlidingWindowBudget(agent_id)
        return self._principal_budgets[agent_id]

    def _get_trace_budget(self, trace_id: str) -> SlidingWindowBudget:
        if trace_id not in self._trace_budgets:
            self._trace_budgets[trace_id] = SlidingWindowBudget(trace_id)
        return self._trace_budgets[trace_id]

    def record_and_evaluate(
        self,
        agent_id: str,
        trace_id: str,
        payload: bytes,
        record_count: int = 1,
        sensitive_record_count: int = 0,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Record event aggregates and evaluate budgets.
        
        CRITICAL: Never stores 'payload'. Only computes length and entropy.
        """
        current_time = now if now is not None else time.time()
        byte_count = len(payload)
        entropy = compute_shannon_entropy(payload)

        # Update principal & trace
        p_budget = self._get_principal_budget(agent_id)
        t_budget = self._get_trace_budget(trace_id)

        p_budget.record(current_time, byte_count, record_count, sensitive_record_count, entropy)
        t_budget.record(current_time, byte_count, record_count, sensitive_record_count, entropy)

        # Evaluate windows
        p_1m_bytes, _, _, p_1m_ent = p_budget.get_window_sum(current_time, 60.0)
        p_1h_bytes, _, _, p_1h_ent = p_budget.get_window_sum(current_time, 3600.0)

        t_1m_bytes, _, _, t_1m_ent = t_budget.get_window_sum(current_time, 60.0)
        t_1h_bytes, _, _, t_1h_ent = t_budget.get_window_sum(current_time, 3600.0)

        max_1m_bytes = max(p_1m_bytes, t_1m_bytes)
        max_1h_bytes = max(p_1h_bytes, t_1h_bytes)
        recent_entropy = max(entropy, t_1m_ent)

        breached = False
        breach_reason = None
        recommended_tier = ContainmentTier.LOG_ONLY

        # Threshold checks:
        # 1. Shannon entropy threshold indicating encrypted or high-entropy exfiltration
        if recent_entropy >= self.thresholds["shannon_entropy_threshold"] and byte_count >= 128:
            breached = True
            breach_reason = f"High Shannon entropy {recent_entropy} >= {self.thresholds['shannon_entropy_threshold']}"
            recommended_tier = ContainmentTier.SHADOW_SANDBOX

        # 2. 1-hour cumulative trace budget breach
        elif t_1h_bytes >= self.thresholds["window_1h_bytes_max"]:
            breached = True
            breach_reason = f"1-hour cumulative trace exfiltration {t_1h_bytes}B >= {self.thresholds['window_1h_bytes_max']}B"
            recommended_tier = ContainmentTier.SHADOW_SANDBOX

        # 3. 1-minute velocity burst trace budget breach
        elif t_1m_bytes >= self.thresholds["window_1m_bytes_max"]:
            breached = True
            breach_reason = f"1-minute cumulative trace exfiltration {t_1m_bytes}B >= {self.thresholds['window_1m_bytes_max']}B"
            recommended_tier = ContainmentTier.DOWNGRADE_SCOPE

        entry = {
            "timestamp": current_time,
            "agent_id": agent_id,
            "trace_id": trace_id,
            "byte_count": byte_count,
            "entropy": entropy,
            "principal_1m_bytes": p_1m_bytes,
            "principal_1h_bytes": p_1h_bytes,
            "trace_1m_bytes": t_1m_bytes,
            "trace_1h_bytes": t_1h_bytes,
            "breached": breached,
            "breach_reason": breach_reason,
            "recommended_tier": recommended_tier.value,
        }

        # Persist ONLY aggregates
        if self.ledger_file:
            self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

        return entry
