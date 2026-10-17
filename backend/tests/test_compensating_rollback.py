"""Tests for Compensating Rollback and Blast Radius DAG (Phase V6).

Verifies:
1. Pre-state checkpoint capture with deterministic SHA-256 state hashes.
2. Rollback execution: walks checkpoints backward, undoes state mutation, and verifies pre-state and post-state hashes match.
3. Irreversible tools: marked IRREVERSIBLE with exact rationale from tool_compensations.yaml.
4. Partial rollback handling: failed compensations mark session PARTIAL without looping.
5. Enforcement path: rollback requires gate authorization.
6. Blast radius DAG contains all nodes (reversible, irreversible, clean) and lineage edges.
7. API endpoint GET /traces/{trace_id}/blast-radius.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.runtime.rollback import RollbackEngine, compute_record_hash
from backend.app.runtime.sandbox_store import SandboxDataStore
from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_rollback_undoes_state_mutation_with_matching_hashes():
    db = SandboxDataStore()
    engine = RollbackEngine()
    session_id = "sess-rollback-001"
    trace_id = "trace-rb-100"
    target_account = "ACC-1001"

    # 1. Snapshot initial state before mutation
    initial_snapshot = db.get_account_snapshot(target_account)
    pre_hash = compute_record_hash(initial_snapshot)

    # 2. Capture checkpoint
    cp = engine.capture_checkpoint(
        session_id=session_id,
        trace_id=trace_id,
        span_id="span-write-1",
        agent_id="customer-bot",
        tool="update_customer_account",
        target_id=target_account,
        pre_state_data=initial_snapshot,
    )
    assert cp.version_hash == pre_hash

    # 3. Adversary mutates account (e.g. unauthorized balance wipe / tier escalation)
    db.mutate_customer_account(target_account, {"balance": 999999.0, "tier": "SUPERADMIN"})
    mutated_snapshot = db.get_account_snapshot(target_account)
    mutated_hash = compute_record_hash(mutated_snapshot)
    assert mutated_hash != pre_hash

    # 4. Execute session rollback
    res = engine.rollback_session(session_id=session_id, sandbox_db=db, gate_authorized=True)
    assert res["overall_status"] == "COMPLETED"
    assert len(res["results"]) == 1
    item = res["results"][0]
    assert item["status"] == "REVERSED"
    assert item["hashes_match"] is True

    # 5. Verify database state is restored exactly to pre-mutation snapshot
    restored_snapshot = db.get_account_snapshot(target_account)
    restored_hash = compute_record_hash(restored_snapshot)
    assert restored_hash == pre_hash
    assert restored_snapshot["balance"] == 5000.0
    assert restored_snapshot["tier"] == "STANDARD"


def test_irreversible_tool_marked_with_reason():
    db = SandboxDataStore()
    engine = RollbackEngine()
    session_id = "sess-rollback-irrev"
    trace_id = "trace-rb-200"

    # Capture checkpoint for irreversible tool (send_external_email)
    engine.capture_checkpoint(
        session_id=session_id,
        trace_id=trace_id,
        span_id="span-email-1",
        agent_id="customer-bot",
        tool="send_external_email",
        target_id="victim@external.com",
        pre_state_data={"status": "not_sent"},
    )

    # Execute rollback
    res = engine.rollback_session(session_id=session_id, sandbox_db=db, gate_authorized=True)
    assert len(res["results"]) == 1
    item = res["results"][0]
    assert item["status"] == "IRREVERSIBLE"
    assert "cannot be recalled" in item["reason"]


def test_failed_compensation_marks_session_partial():
    db = SandboxDataStore()
    engine = RollbackEngine()
    session_id = "sess-rollback-fail"
    trace_id = "trace-rb-300"

    # Checkpoint pointing to a non-existent account ID in DB -> DB will fail compensation
    engine.capture_checkpoint(
        session_id=session_id,
        trace_id=trace_id,
        span_id="span-fail-1",
        agent_id="customer-bot",
        tool="update_customer_account",
        target_id="ACC-GHOST-9999",
        pre_state_data={"account_id": "ACC-GHOST-9999"},
    )

    res = engine.rollback_session(session_id=session_id, sandbox_db=db, gate_authorized=True)
    assert res["overall_status"] == "PARTIAL"
    assert res["results"][0]["status"] == "FAILED"


def test_rollback_refuses_without_gate_authorization():
    db = SandboxDataStore()
    engine = RollbackEngine()
    with pytest.raises(PermissionError, match="ArmorIQ gate authorization"):
        engine.rollback_session("sess-unauth", sandbox_db=db, gate_authorized=False)


def test_blast_radius_dag_and_api(client):
    from backend.app.runtime.rollback import rollback_engine
    trace_id = "trace-dag-test-999"

    # Record sequence of tool calls in DAG
    rollback_engine.record_trace_call(
        trace_id=trace_id,
        span_id="span-root",
        parent_span_id=None,
        agent_id="customer-bot",
        tool="order_status",
        args={"order_id": "ORD-1"},
        is_state_changing=False,
    )
    rollback_engine.record_trace_call(
        trace_id=trace_id,
        span_id="span-child-1",
        parent_span_id="span-root",
        agent_id="customer-bot",
        tool="update_customer_account",
        args={"account_id": "ACC-1001"},
        is_state_changing=True,
    )
    rollback_engine.record_trace_call(
        trace_id=trace_id,
        span_id="span-child-2",
        parent_span_id="span-child-1",
        agent_id="customer-bot",
        tool="send_external_email",
        args={"to": "audit@acme.com"},
        is_state_changing=True,
    )

    # Capture and roll back
    rollback_engine.capture_checkpoint(
        session_id="sess-dag-test",
        trace_id=trace_id,
        span_id="span-child-1",
        agent_id="customer-bot",
        tool="update_customer_account",
        target_id="ACC-1001",
        pre_state_data={"balance": 5000.0},
    )
    rollback_engine.capture_checkpoint(
        session_id="sess-dag-test",
        trace_id=trace_id,
        span_id="span-child-2",
        agent_id="customer-bot",
        tool="send_external_email",
        target_id="audit@acme.com",
        pre_state_data={"status": "unsent"},
    )

    db = SandboxDataStore()
    rollback_engine.rollback_session("sess-dag-test", sandbox_db=db, gate_authorized=True)

    # Query DAG directly
    dag = rollback_engine.build_blast_radius_dag(trace_id)
    assert dag["total_nodes"] == 3
    node_map = {n["id"]: n for n in dag["nodes"]}
    assert node_map["span-root"]["status"] == "NOT_APPLICABLE"
    assert node_map["span-child-1"]["status"] == "REVERSED"
    assert node_map["span-child-2"]["status"] == "IRREVERSIBLE"

    # Query DAG via API
    resp = client.get(f"/traces/{trace_id}/blast-radius")
    assert resp.status_code == 200
    api_dag = resp.json()
    assert api_dag["total_nodes"] == 3
    assert len(api_dag["edges"]) == 2
