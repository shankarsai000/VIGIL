"""Consistency tests for CLAUDE.md architecture guide (Phase DOC-FIX-1).

Verifies:
1. Section 6 of CLAUDE.md is generated from and matches config/thresholds.yaml.
2. Section 4.1 signatures match actual introspected armoriq-sdk==0.6.10 signatures.
3. Section 4.3 exception classes exist in the installed armoriq package.
4. Scenario 6 and antibody candidate replay use the same benign window (600 records).
5. All evidence paths and numeric claims in Sections 7 and 8 match evidence files.
"""
from __future__ import annotations

import inspect
from pathlib import Path
import pytest
import yaml

import armoriq_sdk
from armoriq_sdk import (
    ArmorIQClient,
    ArmorIQException,
    PolicyBlockedException,
    PolicyHoldException,
    InvokeOptions,
)

from scripts.generate_guide_thresholds import verify_section_6, generate_thresholds_yaml_block
from scripts.check_guide_evidence import check_guide_evidence

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GUIDE_PATH = REPO_ROOT / "CLAUDE.md"
THRESHOLDS_PATH = REPO_ROOT / "config" / "thresholds.yaml"


def test_section_6_matches_thresholds_yaml():
    """Verify Section 6 of CLAUDE.md matches generated YAML from config/thresholds.yaml."""
    assert verify_section_6(), "Section 6 of CLAUDE.md does not match config/thresholds.yaml"


def test_sdk_signatures_match_guide():
    """Verify SDK method signatures match the guide's documentation."""
    # 1. capture_plan
    sig_capture = inspect.signature(ArmorIQClient.capture_plan)
    capture_params = list(sig_capture.parameters.keys())
    assert capture_params == ["self", "llm", "prompt", "plan", "metadata"]

    # 2. get_intent_token
    sig_token = inspect.signature(ArmorIQClient.get_intent_token)
    token_params = list(sig_token.parameters.keys())
    assert token_params == ["self", "plan_capture", "policy", "validity_seconds"]

    # 3. invoke_with_policy
    sig_invoke = inspect.signature(ArmorIQClient.invoke_with_policy)
    invoke_params = list(sig_invoke.parameters.keys())
    assert invoke_params == ["self", "mcp", "action", "intent_token", "params", "options"]

    # 4. InvokeOptions fields
    options_fields = list(InvokeOptions.model_fields.keys())
    assert "wait_for_approval" in options_fields
    assert "delegation_timeout_ms" in options_fields
    assert "on_hold" in options_fields


def test_exception_classes_in_guide_exist_in_installed_sdk():
    """Verify that all exception classes in CLAUDE.md Section 4.3 exist in armoriq_sdk."""
    guide_text = GUIDE_PATH.read_text(encoding="utf-8")
    
    # Extract Section 4.3
    start = guide_text.find("### 4.3 Fail-Closed Decision Matrix")
    assert start != -1
    end = guide_text.find("## 5.", start)
    sec_4_3 = guide_text[start:end]

    # Required valid classes
    assert "PolicyBlockedException" in sec_4_3
    assert hasattr(armoriq_sdk, "PolicyBlockedException")

    assert "PolicyHoldException" in sec_4_3
    assert hasattr(armoriq_sdk, "PolicyHoldException")

    # Fictional classes must NOT exist in the guide table
    assert "NetworkError" not in sec_4_3, "Fictional class NetworkError found in Section 4.3"
    assert "SDKError" not in sec_4_3, "Fictional class SDKError found in Section 4.3"


def test_scenario_6_and_replay_use_same_benign_window():
    """Verify Scenario 6 and antibody backtesting use the same window (600 records)."""
    with open(THRESHOLDS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    window = data["policy_immune"]["antibody_backtest_window"]["value"]
    min_benign = data["policy_immune"]["min_benign_records"]["value"]
    assert window == 600
    assert min_benign == 600
    assert window >= 598, "Window must be at least 598 to ensure false block upper bound <= 0.005"


def test_guide_evidence_paths_and_numbers():
    """Verify all evidence paths and Section 7 & 8 numbers match evidence files."""
    errors, warnings = check_guide_evidence()
    assert not errors, f"Evidence validation failed with {len(errors)} error(s): {errors}"
