#!/usr/bin/env python3
"""P0.1: ArmorIQ SDK Smoke Test (no invokes).

Builds an ArmorIQClient from .env, then runs capture_plan and get_intent_token
with an inline allow for vigil-containment/quarantine_agent.
Never prints secret values.
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()

from armoriq_sdk import (
    ArmorIQClient,
    ArmorIQException,
    PolicyBlockedException,
    PolicyHoldException,
)

LLM_IDENTIFIER = "vigil-policy-gate"
ACCEPTED_LLM_FALLBACKS = ["vigil-policy-gate", "gpt-4o", "claude-3-5-sonnet-20241022", "custom"]

def run_smoke():
    api_key = os.getenv("ARMORIQ_API_KEY", "").strip()
    user_email = os.getenv("ARMORIQ_USER_EMAIL", "").strip()
    agent_id = os.getenv("ARMORIQ_AGENT_ID", "vigil-containment").strip()
    use_prod = os.getenv("ARMORIQ_USE_PRODUCTION", "true").lower() in ("true", "1", "yes")

    print(f"=== ArmorIQ SDK Smoke Test ===")
    print(f"Config: user_email_set={bool(user_email)}, agent_id={agent_id}, use_prod={use_prod}")
    print(f"API key present: {bool(api_key)}, length: {len(api_key)}")

    if not api_key or not user_email:
        print("ERROR: Missing ARMORIQ_API_KEY or ARMORIQ_USER_EMAIL in environment.")
        sys.exit(1)

    client = ArmorIQClient(
        api_key=api_key,
        user_id=user_email,
        agent_id=agent_id,
        use_production=use_prod,
    )

    mcp = os.getenv("ARMORIQ_CONTAINMENT_MCP_ID", "vigil-containment")
    tool = "quarantine_agent"
    goal = "Contain compromised agent customer_bot"
    plan = {
        "goal": goal,
        "steps": [
            {"action": tool, "mcp": mcp, "params": {"agent_id": "customer_bot", "reason": "privilege_escalation"}}
        ],
    }

    captured = None
    used_llm = LLM_IDENTIFIER

    for candidate_llm in ACCEPTED_LLM_FALLBACKS:
        try:
            print(f"Testing capture_plan with llm='{candidate_llm}'...")
            captured = client.capture_plan(llm=candidate_llm, prompt=goal, plan=plan)
            used_llm = candidate_llm
            print(f"capture_plan SUCCESS with llm='{used_llm}'! captured type={type(captured).__name__}")
            break
        except Exception as exc:
            print(f"capture_plan exception with llm='{candidate_llm}': {type(exc).__name__}: {exc}")
            if "llm" not in str(exc).lower() and "model" not in str(exc).lower():
                # Not an LLM identifier rejection, break early
                break

    if captured is None:
        print("ERROR: capture_plan failed across all tested LLM identifiers.")
        sys.exit(2)

    try:
        print("Testing get_intent_token with inline allow for vigil-containment/quarantine_agent...")
        policy = {"allow": [f"{mcp}/{tool}"], "deny": []}
        token = client.get_intent_token(captured, policy=policy, validity_seconds=300)
        token_type = type(token).__name__
        # Never print token string
        has_val = bool(getattr(token, "token", None) or str(token))
        print(f"get_intent_token SUCCESS! token_type={token_type}, token_obtained={has_val}")
        print("SMOKE TEST COMPLETED SUCCESSFULLY.")
    except PolicyBlockedException as exc:
        print(f"PolicyBlockedException during get_intent_token: {exc}")
        sys.exit(3)
    except PolicyHoldException as exc:
        print(f"PolicyHoldException during get_intent_token: {exc}")
        sys.exit(4)
    except ArmorIQException as exc:
        print(f"ArmorIQException during get_intent_token: {type(exc).__name__}: {exc}")
        sys.exit(5)
    except Exception as exc:
        print(f"Unexpected exception during get_intent_token: {type(exc).__name__}: {exc}")
        sys.exit(6)

if __name__ == "__main__":
    run_smoke()
