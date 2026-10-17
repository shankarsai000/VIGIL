"""Live Verification Script for Phase V1: Tainted Delegation to BillingAgent.

Runs against production ArmorIQ proxy (https://customer-proxy.armoriq.ai).
Attaches the tainted lineage inline deny policy to get_intent_token, invokes
billing_database, and proves ArmorIQ blocks the call with PolicyBlockedException.
Saves evidence to evidence/V1/live_taint_enforcement.json.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from dotenv import dotenv_values

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from armoriq_sdk import ArmorIQClient, InvokeOptions
from armoriq_sdk.exceptions import PolicyBlockedException

from backend.app.provenance.lineage import ProvenanceTracker, TaintLevel


def run_live_taint_verification():
    vals = dotenv_values(REPO_ROOT / ".env")
    api_key = vals.get("ARMORIQ_API_KEY", "")
    user_email = vals.get("ARMORIQ_USER_EMAIL", "")

    if not api_key or not user_email:
        print("[Live V1] ERROR: ArmorIQ credentials missing in .env")
        sys.exit(1)

    tracker = ProvenanceTracker()
    trace_id = f"trace-live-v1-taint-{int(time.time())}"

    # 1. Simulate multi-hop confused deputy delegation:
    # CustomerBot (External Email) -> AnalyticsAgent -> BillingAgent
    tracker.record_input(
        trace_id=trace_id,
        to_agent="customer-bot",
        input_taint=TaintLevel.EXTERNAL_UNTRUSTED,
        source_label="external_phishing_email",
    )
    tracker.propagate_delegation(
        trace_id=trace_id,
        from_agent="customer-bot",
        to_agent="analytics-agent",
        payload_taint=TaintLevel.VERIFIED_INTERNAL,
        source_label="ticket_summary",
    )
    tracker.propagate_delegation(
        trace_id=trace_id,
        from_agent="analytics-agent",
        to_agent="billing-agent",
        payload_taint=TaintLevel.VERIFIED_INTERNAL,
        source_label="request_export",
    )

    lineage = tracker.get_lineage(trace_id)
    assert lineage.current_taint == TaintLevel.EXTERNAL_UNTRUSTED

    # 2. Derive inline policy for billing_database
    mcp = "vigil-tools"
    target_tool = "billing_database"
    mint_policy = tracker.derive_mint_policy(trace_id, target_tool, mcp)
    policy_dict = {"allow": mint_policy["allow"], "deny": mint_policy["deny"]}

    print(f"[Live V1] Trace ID: {trace_id}")
    print(f"[Live V1] Lineage Taint: {lineage.current_taint.name}")
    print(f"[Live V1] Mint Policy: {policy_dict}")

    client = ArmorIQClient(
        api_key=api_key,
        user_id=user_email,
        agent_id="customer-bot",
        use_production=True,
    )

    plan = {
        "goal": "Export billing accounts under tainted delegation",
        "steps": [{"action": target_tool, "mcp": mcp, "params": {"query": "SELECT * FROM customer_accounts"}}],
    }

    print("[Live V1] Capturing plan...")
    cap = client.capture_plan(llm="claude-3-5-sonnet", prompt=plan["goal"], plan=plan)

    print("[Live V1] Calling get_intent_token with taint policy...")
    token = client.get_intent_token(cap, policy=policy_dict, validity_seconds=300)
    token_id = getattr(token, "token_id", str(token))
    print(f"[Live V1] Token issued: {token_id[:16]}... (Policy attached)")

    # 3. Invoke with policy - ArmorIQ OPA must block
    enforcement_record = {
        "timestamp": round(time.time(), 3),
        "trace_id": trace_id,
        "agent_id": "customer-bot",
        "target_tool": target_tool,
        "mcp_id": mcp,
        "lineage_taint": lineage.current_taint.name,
        "mint_policy": policy_dict,
        "token_id": token_id,
        "decision": "UNKNOWN",
        "exception": None,
    }

    print("[Live V1] Invoking tool through customer proxy...")
    try:
        client.invoke_with_policy(
            mcp,
            target_tool,
            token,
            {"query": "SELECT * FROM customer_accounts"},
            options=InvokeOptions(user_email=user_email, wait_for_approval=False),
        )
        enforcement_record["decision"] = "UNEXPECTED_ALLOW"
        print("[Live V1] ERROR: Tool unexpectedly allowed!")
    except PolicyBlockedException as ex:
        enforcement_record["decision"] = "POLICY_BLOCKED"
        enforcement_record["exception"] = {
            "class": "PolicyBlockedException",
            "message": str(ex),
            "layer": getattr(ex, "layer", "opa"),
            "reason": getattr(ex, "reason", "policy_constraints_not_satisfied"),
        }
        print(f"[Live V1] [PASS] ArmorIQ successfully blocked tool invocation: {ex}")
    except Exception as ex:
        enforcement_record["decision"] = "EXCEPTION"
        enforcement_record["exception"] = {"class": type(ex).__name__, "message": str(ex)}
        print(f"[Live V1] Exception: {type(ex).__name__}: {ex}")

    out_file = REPO_ROOT / "evidence" / "V1" / "live_taint_enforcement.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(enforcement_record, f, indent=2)

    print(f"[Live V1] Evidence saved to: {out_file}")


if __name__ == "__main__":
    run_live_taint_verification()
