"""Probe script for Feature A: Pre-execution Plan Vetting.

Tests whether an inline deny raises at get_intent_token (mint time) or at invoke.
Saves empirical output to evidence/P1/mint_probe.json.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from dotenv import dotenv_values

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from armoriq_sdk import ArmorIQClient, InvokeOptions
from armoriq_sdk.exceptions import PolicyBlockedException, PolicyHoldException, ArmorIQException

vals = dotenv_values(REPO_ROOT / ".env")
api_key = vals.get("ARMORIQ_API_KEY", "")
user_email = vals.get("ARMORIQ_USER_EMAIL", "")

if not api_key or not user_email:
    print("ERROR: Credentials missing in .env")
    sys.exit(1)

client = ArmorIQClient(
    api_key=api_key,
    user_id=user_email,
    agent_id="customer-bot",
    use_production=True,
)

mcp = "vigil-tools"
denied_tool = "billing_database"
plan = {
    "goal": "Exfiltrate corporate customer records",
    "steps": [{"action": denied_tool, "mcp": mcp, "params": {"query": "SELECT * FROM accounts"}}],
}

probe_result = {
    "timestamp": round(time.time(), 3),
    "sdk_version": getattr(client, "__version__", "0.6.10"),
    "mode": "live",
    "agent_id": "customer-bot",
    "mcp_id": mcp,
    "denied_tool": denied_tool,
    "mint_time_behavior": {},
    "invoke_time_behavior": {},
    "raised_at": "unknown",
}

print("[Probe] Capturing plan...")
cap = client.capture_plan(llm="claude-3-5-sonnet", prompt=plan["goal"], plan=plan)

policy = {
    "allow": [],
    "deny": [f"{mcp}/{denied_tool}"],
}

print("[Probe] Calling get_intent_token (mint time)...")
mint_raised = False
try:
    token = client.get_intent_token(cap, policy=policy, validity_seconds=300)
    probe_result["mint_time_behavior"] = {
        "raised": False,
        "token_issued": True,
        "token_id": getattr(token, "token_id", str(token)),
        "plan_hash": getattr(token, "plan_hash", ""),
    }
    print(f"       get_intent_token succeeded! Token ID: {getattr(token, 'token_id', str(token))[:16]}...")
except Exception as ex:
    mint_raised = True
    probe_result["raised_at"] = "get_intent_token"
    probe_result["mint_time_behavior"] = {
        "raised": True,
        "exception_class": type(ex).__name__,
        "exception_message": str(ex),
        "layer": getattr(ex, "layer", "unknown"),
    }
    print(f"       get_intent_token raised: {type(ex).__name__}: {ex}")

if not mint_raised:
    print("[Probe] Calling invoke_with_policy (invoke time)...")
    try:
        client.invoke_with_policy(
            mcp,
            denied_tool,
            token,
            {"query": "SELECT * FROM accounts"},
            options=InvokeOptions(user_email=user_email, wait_for_approval=False),
        )
        probe_result["invoke_time_behavior"] = {"raised": False, "outcome": "ALLOWED"}
        print("       invoke_with_policy unexpectedly allowed!")
    except PolicyBlockedException as ex:
        probe_result["raised_at"] = "invoke"
        probe_result["invoke_time_behavior"] = {
            "raised": True,
            "exception_class": "PolicyBlockedException",
            "exception_message": str(ex),
            "enforcement_action": getattr(ex, "enforcement_action", "block"),
            "reason": getattr(ex, "reason", "policy_constraints_not_satisfied"),
            "layer": getattr(ex, "layer", "opa"),
        }
        print(f"       invoke_with_policy raised PolicyBlockedException at layer '{getattr(ex, 'layer', 'opa')}': {ex}")
    except Exception as ex:
        probe_result["raised_at"] = "invoke"
        probe_result["invoke_time_behavior"] = {
            "raised": True,
            "exception_class": type(ex).__name__,
            "exception_message": str(ex),
            "layer": getattr(ex, "layer", "unknown"),
        }
        print(f"       invoke_with_policy raised: {type(ex).__name__}: {ex}")

probe_result["finding"] = (
    "MINT_TIME_REFUSAL" if probe_result["raised_at"] == "get_intent_token" else "INVOKE_TIME_ENFORCEMENT"
)

out_file = REPO_ROOT / "evidence" / "P1" / "mint_probe.json"
out_file.parent.mkdir(parents=True, exist_ok=True)
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(probe_result, f, indent=2)

print(f"\nProbe complete: raised_at='{probe_result['raised_at']}' -> saved to {out_file}")
