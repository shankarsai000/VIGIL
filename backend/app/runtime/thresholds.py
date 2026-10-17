"""Centralized Threshold Loader (CLAUDE.md Rule H & Phase DOC-FIX-1).

Single source of truth for all system thresholds loaded from config/thresholds.yaml.
Prohibits hardcoded magic float literals across application modules.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
import yaml

_CACHED_THRESHOLDS: Optional[Dict[str, Any]] = None
_THRESHOLDS_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "thresholds.yaml"


def load_raw_thresholds(path: Optional[Path] = None) -> Dict[str, Any]:
    global _CACHED_THRESHOLDS
    target_path = path or _THRESHOLDS_PATH
    if _CACHED_THRESHOLDS is None or path is not None:
        with open(target_path, "r", encoding="utf-8") as f:
            _CACHED_THRESHOLDS = yaml.safe_load(f)
    return _CACHED_THRESHOLDS


def get_threshold(section: str, key: str, subkey: str = "value") -> Any:
    data = load_raw_thresholds()
    sec = data.get(section, {})
    item = sec.get(key, {})
    if isinstance(item, dict):
        return item.get(subkey)
    return item


class SystemThresholds:
    """Convenience accessors for centralized system thresholds."""

    @classmethod
    def anomaly_score(cls) -> float:
        return float(get_threshold("detection", "anomaly_score_threshold", "value"))

    @classmethod
    def escalate(cls) -> float:
        return float(get_threshold("governance", "escalate_threshold", "value"))

    @classmethod
    def quarantine(cls) -> float:
        return float(get_threshold("governance", "quarantine_threshold", "value"))

    @classmethod
    def log_only_ceiling(cls) -> float:
        return float(get_threshold("containment_ladder", "log_only_ceiling", "value"))

    @classmethod
    def downgrade_min(cls) -> float:
        return float(get_threshold("containment_ladder", "surgical_downgrade_range", "min"))

    @classmethod
    def downgrade_max(cls) -> float:
        return float(get_threshold("containment_ladder", "surgical_downgrade_range", "max"))

    @classmethod
    def shadow_min(cls) -> float:
        return float(get_threshold("containment_ladder", "mirage_honeypot_range", "min"))

    @classmethod
    def shadow_max(cls) -> float:
        return float(get_threshold("containment_ladder", "mirage_honeypot_range", "max"))

    @classmethod
    def min_coverage(cls) -> float:
        return float(get_threshold("policy_immune", "min_coverage", "value"))

    @classmethod
    def min_recall(cls) -> float:
        return float(get_threshold("policy_immune", "min_coverage", "value"))

    @classmethod
    def max_false_block_upper(cls) -> float:
        return float(get_threshold("policy_immune", "max_false_block_upper", "value"))

    @classmethod
    def antibody_backtest_window(cls) -> int:
        return int(get_threshold("policy_immune", "antibody_backtest_window", "value"))

    @classmethod
    def min_benign_records(cls) -> int:
        return int(get_threshold("policy_immune", "min_benign_records", "value"))
