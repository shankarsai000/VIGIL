"""Live verification tests against real ArmorIQ control plane and customer proxy.

Marked with @pytest.mark.live. Skipped automatically unless ARMORIQ_MODE=live and credentials are set.
"""

import os
import pytest
from dotenv import load_dotenv

load_dotenv()

from armoriq_sdk import ArmorIQClient, InvokeOptions
from armoriq_sdk.exceptions import PolicyBlockedException

API_KEY = os.getenv("ARMORIQ_API_KEY", "")
USER_EMAIL = os.getenv("ARMORIQ_USER_EMAIL", "")
AGENT_ID = os.getenv("ARMORIQ_AGENT_ID", "vigil-containment-v2")
MODE = os.getenv("ARMORIQ_MODE", "disabled").lower()

LIVE_AVAILABLE = (MODE == "live" and bool(API_KEY) and bool(USER_EMAIL))


@pytest.mark.live
def test_live_armoriq_plan_capture_and_mint_token():
    if not LIVE_AVAILABLE:
        pytest.skip("Skipping live ArmorIQ test: ARMORIQ_MODE is not live or credentials missing")

    client = ArmorIQClient(
        api_key=API_KEY,
        user_id=USER_EMAIL,
        agent_id=AGENT_ID,
        use_production=True,
    )

    plan = {
        "goal": "Verify live agent plan capture",
        "steps": [{"action": "quarantine_agent", "mcp": AGENT_ID, "params": {}}],
    }
    captured = client.capture_plan(llm="vigil-policy-gate", prompt=plan["goal"], plan=plan)
    assert captured is not None
    assert "plan" in captured or hasattr(captured, "plan")

    token = client.get_intent_token(
        captured,
        policy={"allow": [f"{AGENT_ID}/quarantine_agent"], "deny": []},
        validity_seconds=120,
    )
    assert token is not None
    assert token.token_id is not None
    assert token.plan_hash is not None


@pytest.mark.live
def test_live_armoriq_governed_invoke():
    if not LIVE_AVAILABLE:
        pytest.skip("Skipping live ArmorIQ test: ARMORIQ_MODE is not live or credentials missing")

    client = ArmorIQClient(
        api_key=API_KEY,
        user_id=USER_EMAIL,
        agent_id=AGENT_ID,
        use_production=True,
    )

    plan = {
        "goal": "Execute live quarantine test",
        "steps": [{"action": "quarantine_agent", "mcp": AGENT_ID, "params": {}}],
    }
    captured = client.capture_plan(llm="vigil-policy-gate", prompt=plan["goal"], plan=plan)
    token = client.get_intent_token(
        captured,
        policy={"allow": [f"{AGENT_ID}/quarantine_agent"], "deny": []},
        validity_seconds=120,
    )

    result = client.invoke_with_policy(
        AGENT_ID,
        "quarantine_agent",
        token,
        {"agent_id": "customer_bot", "reason": "LIVE_TEST", "score": 0.99},
        options=InvokeOptions(user_email=USER_EMAIL, wait_for_approval=False),
    )
    assert getattr(result, "status", None) == "success"


@pytest.mark.live
def test_live_armoriq_denies_unauthorized_tool():
    if not LIVE_AVAILABLE:
        pytest.skip("Skipping live ArmorIQ test: ARMORIQ_MODE is not live or credentials missing")

    client = ArmorIQClient(
        api_key=API_KEY,
        user_id=USER_EMAIL,
        agent_id=AGENT_ID,
        use_production=True,
    )

    plan = {
        "goal": "Test policy block on destructive operation",
        "steps": [{"action": "drop_database", "mcp": AGENT_ID, "params": {}}],
    }
    captured = client.capture_plan(llm="vigil-policy-gate", prompt=plan["goal"], plan=plan)
    token = client.get_intent_token(
        captured,
        policy={"allow": [f"{AGENT_ID}/quarantine_agent"], "deny": [f"{AGENT_ID}/drop_database"]},
        validity_seconds=120,
    )

    with pytest.raises(PolicyBlockedException):
        client.invoke_with_policy(
            AGENT_ID,
            "drop_database",
            token,
            {"agent_id": "test_agent"},
            options=InvokeOptions(user_email=USER_EMAIL, wait_for_approval=False),
        )
