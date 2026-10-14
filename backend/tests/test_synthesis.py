"""Incident-to-policy synthesis tests (offline)."""
from backend.app.policies.synthesis import CallRecord, synthesize

ATTACK = [
    CallRecord("customer_bot", "TOOL_CALL", "billing_database"),
    CallRecord("customer_bot", "TOOL_CALL", "billing_database"),
    CallRecord("customer_bot", "TOOL_CALL", "delete_all_billing_records"),
    CallRecord("customer_bot", "AGENT_DELEGATION", "billing_agent"),
]
BENIGN = [
    CallRecord("customer_bot", "TOOL_CALL", "order_status"),
    CallRecord("customer_bot", "QUERY", "user_input"),
    # Another agent may use billing_database legitimately. That must not block the rule for customer_bot.
    CallRecord("analytics_agent", "TOOL_CALL", "billing_database"),
]


def test_proposes_one_deny_rule_per_attacked_tool_with_zero_benign_hits():
    report = synthesize(ATTACK, BENIGN, mcp_id="vigil-tools")
    assert sorted(p.deny for p in report.proposals) == [
        "vigil-tools.billing_database",
        "vigil-tools.delete_all_billing_records",
    ]
    assert all(p.benign_calls_blocked == 0 for p in report.proposals)
    assert report.skipped_non_tool_calls == 1  # the delegation is not a tool call, so no glob is written for it


def test_a_tool_the_same_agent_uses_legitimately_is_rejected_with_a_reason():
    benign = BENIGN + [CallRecord("customer_bot", "TOOL_CALL", "billing_database")]
    report = synthesize(ATTACK, benign, mcp_id="vigil-tools")
    assert "vigil-tools.billing_database" not in [p.deny for p in report.proposals]
    assert any("billing_database" in reason for reason in report.rejected)


def test_unsafe_tool_names_never_become_globs():
    report = synthesize([CallRecord("agent", "TOOL_CALL", "x*; drop")], [], mcp_id="m")
    assert report.proposals == []
    assert report.rejected


def test_the_yaml_patch_is_reviewable_per_agent():
    text = synthesize(ATTACK, BENIGN, mcp_id="vigil-tools").to_yaml_patch()
    assert "config/customer_bot.armoriq.yaml" in text
    assert "- vigil-tools.billing_database" in text
    assert "Review each one" in text
