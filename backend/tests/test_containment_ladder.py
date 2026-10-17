"""Tests for Graduated Containment Ladder (Phase V2).

Covers:
1. Boundary tests for select_containment_tier pure function (table-driven).
2. Criticality rule: CRITICAL agents never receive LOG_ONLY.
3. Canary tripwire rule: canary hit forces immediate QUARANTINE_ROLLBACK.
4. Monotonic escalation within session.
5. Human release workflow restoring session tier.
6. Mirage synthetic database zero-intersection isolation test.
7. Side-by-side execution: shadowed vs unshadowed session data separation.
8. API route protection for /internal/containment/downgrade, shadow, rollback, and session endpoints.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient

from backend.app.policies.containment_ladder import (
    ContainmentTier,
    SessionContainmentManager,
    select_containment_tier,
    load_containment_thresholds,
)
from backend.app.runtime.mirage import MirageDatabase, mirage_db
from backend.app.policies.tools_mcp import billing_database, containment_manager as tools_containment_mgr
from backend.app.api import security
from backend.main import app

OP_KEY = "op-key-test-v2-12345"
CS_SECRET = "cs-secret-test-v2-67890"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def security_keys(monkeypatch):
    monkeypatch.setattr(security, "settings", SimpleNamespace(operator_api_key=OP_KEY, containment_secret=CS_SECRET))


# 1. Pure function table-driven boundary tests
@pytest.mark.parametrize(
    "score,criticality,canary_hit,expected_tier",
    [
        # LOG_ONLY boundary (< 0.45)
        (0.00, "LOW", False, ContainmentTier.LOG_ONLY),
        (0.20, "MEDIUM", False, ContainmentTier.LOG_ONLY),
        (0.449, "LOW", False, ContainmentTier.LOG_ONLY),
        # Critical agent rule: never LOG_ONLY even when score is low
        (0.00, "CRITICAL", False, ContainmentTier.DOWNGRADE_SCOPE),
        (0.30, "CRITICAL", False, ContainmentTier.DOWNGRADE_SCOPE),
        (0.449, "CRITICAL", False, ContainmentTier.DOWNGRADE_SCOPE),
        # DOWNGRADE_SCOPE range [0.45, 0.75)
        (0.45, "LOW", False, ContainmentTier.DOWNGRADE_SCOPE),
        (0.60, "MEDIUM", False, ContainmentTier.DOWNGRADE_SCOPE),
        (0.749, "CRITICAL", False, ContainmentTier.DOWNGRADE_SCOPE),
        # SHADOW_SANDBOX range [0.75, 0.90)
        (0.75, "LOW", False, ContainmentTier.SHADOW_SANDBOX),
        (0.80, "MEDIUM", False, ContainmentTier.SHADOW_SANDBOX),
        (0.899, "CRITICAL", False, ContainmentTier.SHADOW_SANDBOX),
        # QUARANTINE_ROLLBACK (>= 0.90)
        (0.90, "LOW", False, ContainmentTier.QUARANTINE_ROLLBACK),
        (0.95, "MEDIUM", False, ContainmentTier.QUARANTINE_ROLLBACK),
        (1.00, "CRITICAL", False, ContainmentTier.QUARANTINE_ROLLBACK),
        # Canary tripwire: triggers QUARANTINE_ROLLBACK regardless of score
        (0.00, "LOW", True, ContainmentTier.QUARANTINE_ROLLBACK),
        (0.20, "MEDIUM", True, ContainmentTier.QUARANTINE_ROLLBACK),
        (0.50, "CRITICAL", True, ContainmentTier.QUARANTINE_ROLLBACK),
    ],
)
def test_select_containment_tier_boundaries(score, criticality, canary_hit, expected_tier):
    tier = select_containment_tier(score=score, criticality=criticality, canary_hit=canary_hit)
    assert tier == expected_tier


# 2. Monotonic escalation tests
def test_monotonic_escalation_within_session():
    mgr = SessionContainmentManager()
    session_id = "sess-monotonic-001"

    assert mgr.get_tier(session_id) == ContainmentTier.LOG_ONLY

    # Escalate to DOWNGRADE_SCOPE
    tier1 = mgr.escalate_session(session_id, ContainmentTier.DOWNGRADE_SCOPE, reason="score 0.50")
    assert tier1 == ContainmentTier.DOWNGRADE_SCOPE
    assert mgr.get_tier(session_id) == ContainmentTier.DOWNGRADE_SCOPE

    # Attempt automatic de-escalation to LOG_ONLY -> must be ignored
    tier_ignored = mgr.escalate_session(session_id, ContainmentTier.LOG_ONLY, reason="lower score")
    assert tier_ignored == ContainmentTier.DOWNGRADE_SCOPE
    assert mgr.get_tier(session_id) == ContainmentTier.DOWNGRADE_SCOPE

    # Escalate to SHADOW_SANDBOX
    tier2 = mgr.escalate_session(session_id, ContainmentTier.SHADOW_SANDBOX, reason="score 0.80")
    assert tier2 == ContainmentTier.SHADOW_SANDBOX

    # Attempt lower tier -> still stays SHADOW_SANDBOX
    tier_ignored2 = mgr.escalate_session(session_id, ContainmentTier.DOWNGRADE_SCOPE, reason="ignore")
    assert tier_ignored2 == ContainmentTier.SHADOW_SANDBOX

    # Escalate to QUARANTINE_ROLLBACK
    tier3 = mgr.escalate_session(session_id, ContainmentTier.QUARANTINE_ROLLBACK, reason="score 0.95")
    assert tier3 == ContainmentTier.QUARANTINE_ROLLBACK

    # Human release resets containment tier
    released_tier = mgr.release_session(session_id, operator_id="admin-shankar", reason="investigated false positive")
    assert released_tier == ContainmentTier.LOG_ONLY
    assert mgr.get_tier(session_id) == ContainmentTier.LOG_ONLY


# 3. Mirage synthetic sandbox database isolation test
def test_mirage_synthetic_isolation_and_zero_real_data():
    db = MirageDatabase(seed=99)
    res = db.query("SELECT * FROM billing_records", session_id="test-mirage-sess")

    assert res["source"] == "MIRAGE_SYNTHETIC_DATABASE"
    assert res["rows_returned"] > 0
    records = res["records"]

    real_sample_records = [
        {"account_id": "REAL-ACT-9901", "invoice_id": "INV-1001", "amount": 450.00},
        {"account_id": "REAL-ACT-9902", "invoice_id": "INV-1002", "amount": 1200.50},
    ]

    # Prove zero intersection between Mirage and real records
    assert db.verify_no_real_rows(real_sample_records) is True

    # Check that all records in Mirage are explicitly tagged as synthetic
    for r in records:
        assert r["is_synthetic"] is True
        assert r["account_id"].startswith("SYNTH-ACT-")
        assert r["invoice_id"].startswith("MIRAGE-INV-")


# 4. Side-by-side session execution test
def test_side_by_side_shadowed_and_unshadowed_sessions():
    async def _run():
        sess_normal = "sess-normal-real-001"
        sess_shadow = "sess-tainted-shadow-002"

        # Set sess_shadow to SHADOW_SANDBOX
        tools_containment_mgr.escalate_session(
            sess_shadow, ContainmentTier.SHADOW_SANDBOX, reason="honeypot test"
        )

        # 1. Unshadowed session query
        res_normal = await billing_database("SELECT * FROM accounts", session_id=sess_normal)
        assert res_normal["source"] == "REAL_SANDBOX_DATABASE"
        for r in res_normal["sample"]:
            assert r["account_id"].startswith("REAL-ACT-")

        # 2. Shadowed session query
        res_shadow = await billing_database("SELECT * FROM accounts", session_id=sess_shadow)
        assert res_shadow["source"] == "MIRAGE_SYNTHETIC_DATABASE"
        assert res_shadow["containment_notice"] == "SHADOW_ROUTED_SYNTHETIC_DATA"
        for r in res_shadow["records"]:
            assert r["account_id"].startswith("SYNTH-ACT-")

    asyncio.run(_run())


# 5. API routes: containment callbacks & session queries
def test_containment_api_routes(client, security_keys):
    session_id = "sess-api-test-01"

    # A. Unauthenticated /internal/containment calls rejected
    assert client.post("/internal/containment/downgrade", json={"session_id": session_id}).status_code == 401
    assert client.post("/internal/containment/shadow", json={"session_id": session_id}).status_code == 401
    assert client.post("/internal/containment/rollback", json={"session_id": session_id}).status_code == 401

    # B. Authorized downgrade
    resp_down = client.post(
        "/internal/containment/downgrade",
        json={"session_id": session_id, "reason": "threat 0.60", "score": 0.60},
        headers={"X-Containment-Secret": CS_SECRET},
    )
    assert resp_down.status_code == 200
    assert resp_down.json()["status"] == "downgraded"
    assert resp_down.json()["tier"] == "DOWNGRADE_SCOPE"

    # C. Query GET /sessions/{id}/containment
    resp_query = client.get(f"/sessions/{session_id}/containment")
    assert resp_query.status_code == 200
    info = resp_query.json()
    assert info["session_id"] == session_id
    assert info["tier"] == "DOWNGRADE_SCOPE"

    # D. Authorized shadow
    resp_shadow = client.post(
        "/internal/containment/shadow",
        json={"session_id": session_id, "reason": "threat 0.82", "score": 0.82},
        headers={"X-Containment-Secret": CS_SECRET},
    )
    assert resp_shadow.status_code == 200
    assert resp_shadow.json()["tier"] == "SHADOW_SANDBOX"

    # E. Authorized rollback
    resp_roll = client.post(
        "/internal/containment/rollback",
        json={"session_id": session_id, "reason": "threat 0.95", "score": 0.95},
        headers={"X-Containment-Secret": CS_SECRET},
    )
    assert resp_roll.status_code == 200
    assert resp_roll.json()["tier"] == "QUARANTINE_ROLLBACK"

    # F. Human release requires operator key
    assert client.post(f"/sessions/{session_id}/release", json={"reason": "audit"}).status_code == 401
    resp_rel = client.post(
        f"/sessions/{session_id}/release",
        json={"reason": "released by human operator", "operator_id": "operator-shankar"},
        headers={"X-VIGIL-Operator-Key": OP_KEY},
    )
    assert resp_rel.status_code == 200
    assert resp_rel.json()["tier"] == "LOG_ONLY"
