"""Tests for ArmorIQ SDK v0.6.10 Signatures and Gate Call Compliance (Phase DOC-FIX-1).

Verifies:
1. Exact parameter names of ArmorIQClient methods: capture_plan, get_intent_token, invoke_with_policy, and InvokeOptions.
2. The gate (ArmorIQGate._authorize_sync) passes valid keyword and positional arguments matching the real SDK signatures.
3. PolicyBlockedException attributes and metadata layer value ('opa').
4. All documented ArmorIQ exception classes exist in the installed armoriq-sdk package.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
import pytest

import armoriq_sdk
from armoriq_sdk import (
    ArmorIQClient,
    ArmorIQException,
    ConfigurationException,
    DelegationException,
    IntentMismatchException,
    InvalidTokenException,
    InvokeOptions,
    MCPInvocationException,
    PolicyBlockedException,
    PolicyHoldException,
    RevokedTokenError,
    TokenExpiredException,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_armoriq_sdk_signatures():
    """Verify exact signatures of ArmorIQ SDK v0.6.10 methods."""
    # capture_plan
    sig_cap = inspect.signature(ArmorIQClient.capture_plan)
    param_names_cap = list(sig_cap.parameters.keys())
    assert "llm" in param_names_cap
    assert "prompt" in param_names_cap
    assert "plan" in param_names_cap
    assert "metadata" in param_names_cap

    # get_intent_token
    sig_token = inspect.signature(ArmorIQClient.get_intent_token)
    param_names_token = list(sig_token.parameters.keys())
    assert "plan_capture" in param_names_token
    assert "policy" in param_names_token
    assert "validity_seconds" in param_names_token

    # invoke_with_policy
    sig_invoke = inspect.signature(ArmorIQClient.invoke_with_policy)
    param_names_invoke = list(sig_invoke.parameters.keys())
    assert "mcp" in param_names_invoke
    assert "action" in param_names_invoke
    assert "intent_token" in param_names_invoke
    assert "params" in param_names_invoke
    assert "options" in param_names_invoke

    # InvokeOptions (Pydantic model constructor signature)
    sig_opt = inspect.signature(InvokeOptions)
    param_names_opt = list(sig_opt.parameters.keys())
    assert "wait_for_approval" in param_names_opt
    assert "user_email" in param_names_opt


def test_gate_calls_match_sdk_parameters():
    """AST check verifying parameter names passed by armoriq_gate._authorize_sync."""
    gate_file = REPO_ROOT / "backend" / "app" / "policies" / "armoriq_gate.py"
    tree = ast.parse(gate_file.read_text(encoding="utf-8"))

    calls_found = {"capture_plan": False, "get_intent_token": False, "invoke_with_policy": False, "InvokeOptions": False}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Check capture_plan call
            if isinstance(node.func, ast.Attribute) and node.func.attr == "capture_plan":
                calls_found["capture_plan"] = True
                kw = [k.arg for k in node.keywords]
                assert "llm" in kw
                assert "prompt" in kw
                assert "plan" in kw

            # Check get_intent_token call
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get_intent_token":
                calls_found["get_intent_token"] = True
                kw = [k.arg for k in node.keywords]
                assert "policy" in kw
                assert "validity_seconds" in kw

            # Check invoke_with_policy call
            if isinstance(node.func, ast.Attribute) and node.func.attr == "invoke_with_policy":
                calls_found["invoke_with_policy"] = True
                # Passed positional: mcp, action, token, params, and kw: options
                kw = [k.arg for k in node.keywords]
                assert "options" in kw
                assert len(node.args) >= 4  # mcp, action, token, params

            # Check InvokeOptions call
            if (isinstance(node.func, ast.Name) and node.func.id == "InvokeOptions") or (
                isinstance(node.func, ast.Attribute) and node.func.attr == "InvokeOptions"
            ):
                calls_found["InvokeOptions"] = True
                kw = [k.arg for k in node.keywords]
                assert "user_email" in kw
                assert "wait_for_approval" in kw

    assert all(calls_found.values()), f"Missing expected SDK calls in gate: {calls_found}"


def test_policy_blocked_exception_structure():
    """Verify PolicyBlockedException attributes and metadata layer value."""
    exc = PolicyBlockedException(
        "Tool 'billing_database' denied by OPA",
        enforcement_action="block",
        reason="policy_constraints_not_satisfied",
        metadata={"layer": "opa"},
    )
    assert exc.enforcement_action == "block"
    assert exc.reason == "policy_constraints_not_satisfied"
    assert hasattr(exc, "metadata")
    assert exc.metadata.get("layer") == "opa"


def test_confirmed_exception_classes_exist():
    """Confirm all documented exception classes exist in armoriq_sdk."""
    expected_classes = [
        "ArmorIQException",
        "ConfigurationException",
        "DelegationException",
        "IntentMismatchException",
        "InvalidTokenException",
        "MCPInvocationException",
        "PolicyBlockedException",
        "PolicyHoldException",
        "RevokedTokenError",
        "TokenExpiredException",
    ]
    for cls_name in expected_classes:
        assert hasattr(armoriq_sdk, cls_name), f"Missing expected class {cls_name} in armoriq_sdk"

    # Confirm fictional classes do NOT exist
    assert not hasattr(armoriq_sdk, "NetworkError")
    assert not hasattr(armoriq_sdk, "Timeout")
    assert not hasattr(armoriq_sdk, "SDKError")
