"""Generator and verifier for Section 6 of CLAUDE.md from config/thresholds.yaml.

Ensures that the thresholds documented in CLAUDE.md §6 are 100% generated from
and synchronized with config/thresholds.yaml.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "config" / "thresholds.yaml"
GUIDE_PATH = REPO_ROOT / "CLAUDE.md"


def generate_thresholds_yaml_block() -> str:
    """Generate the formatted YAML code block for CLAUDE.md §6."""
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    det = data.get("detection", {})
    ladder = data.get("containment_ladder", {})
    gov = data.get("governance", {})
    prov = data.get("provenance_and_lineage", {})
    budg = data.get("low_and_slow_budgets", {})
    immune = data.get("policy_immune", {})

    lines = [
        "```yaml",
        "detection:",
        f"  anomaly_score_threshold: {det['anomaly_score_threshold']['value']:.2f}       # Base Isolation Forest / heuristic threshold",
        "",
        "containment_ladder:",
        f"  log_only_ceiling: {ladder['log_only_ceiling']['value']:.2f}              # Tier 1 ceiling",
        f"  surgical_downgrade_range: [{ladder['surgical_downgrade_range']['min']:.2f}, {ladder['surgical_downgrade_range']['max']:.2f}]  # Tier 2 range",
        f"  mirage_honeypot_range: [{ladder['mirage_honeypot_range']['min']:.2f}, {ladder['mirage_honeypot_range']['max']:.2f}]     # Tier 3 range",
        f"  quarantine_rollback_threshold: {ladder['quarantine_rollback_threshold']['value']:.2f}     # Unified system-wide quarantine and rollback trigger",
        "",
        "governance:",
        f"  escalate_threshold: {gov['escalate_threshold']['value']:.2f}            # Human approval escalation threshold in gate",
        f"  quarantine_threshold: {gov['quarantine_threshold']['value']:.2f}          # Single unified quarantine threshold",
        "",
        "provenance_and_lineage:",
        f"  max_delegation_depth: {prov['max_delegation_depth']['value']}             # Max hops before DEGRADED",
        "  restricted_sink_ceilings:",
    ]

    sinks = prov.get("restricted_sink_ceilings", {})
    for sink_name, sink_info in sinks.items():
        ceiling = sink_info.get("ceiling", "SYSTEM_TRUSTED") if isinstance(sink_info, dict) else sink_info
        lines.append(f'    {sink_name}: "{ceiling}"')

    lines.extend([
        "",
        "low_and_slow_budgets:",
        f"  window_1m_bytes_max: {budg['window_1m_bytes_max']['value']}          # 10 KB / 1-minute window (inclusive >=)",
        f"  window_1h_bytes_max: {budg['window_1h_bytes_max']['value']}         # 100 KB / 1-hour window (inclusive >=)",
        f"  shannon_entropy_threshold: {budg['shannon_entropy_threshold']['value']:.1f}      # Shannon entropy threshold (bits)",
        f"  canary_hit_trigger_count: {budg['canary_hit_trigger_count']['value']}         # 1 hit triggers instant quarantine",
        "",
        "policy_immune:",
        f"  min_coverage: {immune['min_coverage']['value']:.2f}                  # 90% attack coverage required",
        f"  max_false_block_upper: {immune['max_false_block_upper']['value']:.3f}        # 0.5% max Clopper-Pearson upper bound",
        f"  min_benign_records: {immune['min_benign_records']['value']}             # Minimum historical baseline records",
        f"  min_attack_records: {immune['min_attack_records']['value']}               # Minimum incident traces",
        f"  delta_significance: {immune['delta_significance']['value']:.2f}            # 95% Confidence Level (1 - delta)",
        f"  antibody_backtest_window: {immune['antibody_backtest_window']['value']}       # 600 benign events replayed for antibodies",
        "```",
    ])

    return "\n".join(lines)


def get_current_section_6(guide_content: str) -> str:
    """Extract Section 6 YAML block from CLAUDE.md."""
    match = re.search(r"## 6\. Single Source of Truth: Centralized Thresholds.*?(```yaml\n.*?\n```)", guide_content, re.DOTALL)
    if not match:
        raise ValueError("Could not find Section 6 YAML block in CLAUDE.md")
    return match.group(1)


def verify_section_6() -> bool:
    """Verify that CLAUDE.md §6 matches generated YAML block."""
    if not GUIDE_PATH.exists() or not CONFIG_PATH.exists():
        return False
    guide_content = GUIDE_PATH.read_text(encoding="utf-8")
    expected_block = generate_thresholds_yaml_block()
    current_block = get_current_section_6(guide_content)
    return current_block.strip() == expected_block.strip()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate or verify Section 6 of CLAUDE.md")
    parser.add_argument("--check", action="store_true", help="Check if Section 6 matches thresholds.yaml")
    args = parser.parse_args()

    if args.check:
        if verify_section_6():
            print("[PASS] CLAUDE.md Section 6 matches config/thresholds.yaml")
            sys.exit(0)
        else:
            print("[FAIL] CLAUDE.md Section 6 differs from config/thresholds.yaml")
            sys.exit(1)
    else:
        print(generate_thresholds_yaml_block())
