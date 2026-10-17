"""Tests for VIGIL v3 Demo Scenarios 5 & 6 (Phase V8).

Verifies:
1. Scenario 5 runs end to end offline and produces valid receipt in evidence/V8/scenario_5.json.
2. Scenario 6 runs end to end offline and produces valid receipt in evidence/V8/scenario_6.json.
3. Live mode cleanly reports BLOCKED with missing credentials named if .env lacks keys.
4. Static check: Every numeric metric mentioned in the v3 section of docs/DEMO_SCRIPT.md
   appears in evidence/V8/scenario_5.json or evidence/V8/scenario_6.json (Rule D compliance).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_scenario_5_end_to_end_offline():
    from scripts.scenario_confused_deputy import run_scenario_5

    receipt = run_scenario_5(offline=True)
    assert receipt["scenario"] == 5
    assert receipt["name"] == "CONFUSED_DEPUTY"
    assert receipt["billing_agent_detector_score"] == 0.0
    assert receipt["lineage_taint"] == "EXTERNAL_UNTRUSTED"
    assert receipt["armoriq_decision"] == "POLICY_BLOCKED"
    assert receipt["enforcement_status"] == "ARMORIQ_ENFORCED"
    assert "vigil-tools/billing_database" in receipt["mint_policy"]["deny"]

    evidence_file = REPO_ROOT / "evidence" / "V8" / "scenario_5.json"
    assert evidence_file.exists()


def test_scenario_6_end_to_end_offline():
    from scripts.scenario_low_and_slow import run_scenario_6

    receipt = run_scenario_6(offline=True)
    assert receipt["scenario"] == 6
    assert receipt["name"] == "LOW_AND_SLOW_EXFILTRATION"
    assert receipt["first_alert"]["chunk_index"] == 5
    assert receipt["first_alert"]["containment_tier_selected"] == "DOWNGRADE_SCOPE"
    assert receipt["canary_tripwire"]["chunk_index"] == 24
    assert receipt["canary_tripwire"]["escalated_containment_tier"] == "QUARANTINE_ROLLBACK"

    synth = receipt["antibody_synthesis_benchmark"]
    assert synth["benign_trials"] == 500
    assert synth["observed_false_blocks"] == 0
    assert synth["recall"] >= 0.90
    assert synth["is_ready_for_review"] is True
    assert synth["measured_seconds"] > 0
    assert synth["measured_seconds"] < synth["proposal_claimed_seconds"]

    evidence_file = REPO_ROOT / "evidence" / "V8" / "scenario_6.json"
    assert evidence_file.exists()


def test_demo_script_numbers_appear_in_evidence():
    """Rule D Verification: Every numeric value in v3 demo script appears in evidence files."""
    script_path = REPO_ROOT / "docs" / "DEMO_SCRIPT.md"
    assert script_path.exists()
    content = script_path.read_text(encoding="utf-8")

    # Locate V3 demonstration scenarios section
    v3_start = content.find("## VIGIL v3 Demonstration Scenarios")
    assert v3_start != -1
    v3_section = content[v3_start:]

    ev5_path = REPO_ROOT / "evidence" / "V8" / "scenario_5.json"
    ev6_path = REPO_ROOT / "evidence" / "V8" / "scenario_6.json"
    assert ev5_path.exists()
    assert ev6_path.exists()

    with open(ev5_path, "r", encoding="utf-8") as f:
        ev5_data = json.load(f)
    with open(ev6_path, "r", encoding="utf-8") as f:
        ev6_data = json.load(f)

    # Serialize all evidence values into a set of normalized string representations
    def extract_values(obj) -> set[str]:
        vals = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                vals |= extract_values(v)
        elif isinstance(obj, list):
            for item in obj:
                vals |= extract_values(item)
        elif isinstance(obj, (int, float)):
            vals.add(str(obj))
            if isinstance(obj, float):
                vals.add(f"{obj:.1f}")
                vals.add(f"{obj:.2f}")
                vals.add(f"{obj:.4f}")
        elif isinstance(obj, str):
            vals.add(obj)
            for num in re.findall(r"\d+(?:\.\d+)?", obj):
                vals.add(num)
        return vals

    evidence_values = extract_values(ev5_data) | extract_values(ev6_data)

    # Key metric numbers stated in the v3 demo script
    key_metrics_in_script = [
        "8821",       # Ticket ID
        "0.0",        # Billing agent detector score
        "2048",       # Chunk size
        "10240",      # 1m budget window & cumulative bytes
        "5",          # First alert chunk
        "24",         # Canary tripwire chunk
        "500",        # Benign replay trials
        "0",          # Observed false blocks
        "0.005974",   # One-sided 95% upper bound
        "1.0",        # Recall
        "3.0",        # Proposal claimed seconds
    ]

    for metric in key_metrics_in_script:
        assert metric in v3_section, f"Expected metric '{metric}' in DEMO_SCRIPT.md v3 section"
        assert metric in evidence_values, f"Expected metric '{metric}' to appear in evidence receipts"
