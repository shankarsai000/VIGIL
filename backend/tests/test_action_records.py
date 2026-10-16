"""Tests for Phase M1: Action Records, Structural Redaction, and Label Governance."""

import asyncio
import os
import time
from types import SimpleNamespace
from typing import Dict, Any
import pytest
from fastapi.testclient import TestClient

from backend.app.api import security
from backend.app.runtime.models import (
    AgentEvent,
    AgentProfile,
    AgentStatus,
    EventType,
    DetectionResult,
    Confidence,
    ThreatType,
    PolicyDecision,
    IncidentRecord,
)
from backend.app.runtime.registry import AgentRegistry
from backend.app.immune.records import ActionRecord, compute_arg_shape
from backend.app.telemetry.monitor import BehavioralMonitor
from backend.tests.fixtures.make_traces import generate_action_records
from backend.main import app

OP_KEY = "op-test-key-12345"
SECRET_PLANT = "SECRET_TOKEN_XYZ_9876543210_SUPER_CONFIDENTIAL_KEY"


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setattr(
        security,
        "settings",
        SimpleNamespace(operator_api_key=OP_KEY, containment_secret="cs-test-secret"),
    )


class MockDetector:
    def __init__(self, score_to_return: float = 0.95):
        self.score_to_return = score_to_return
        self.ewma = SimpleNamespace(
            update=lambda *args: None,
            increment_count=lambda *args: None,
        )

    async def detect(self, event, profile, window_stats, v2_signals=None):
        return DetectionResult(
            score=self.score_to_return,
            threat_type=ThreatType.PROMPT_INJECTION,
            confidence=Confidence.CRITICAL,
            rule_score=self.score_to_return,
            ewma_score=self.score_to_return,
            iforest_score=self.score_to_return,
            details={"mock": True},
        )


class MockExecutor:
    async def respond(self, event, detection_result, profile):
        return SimpleNamespace(
            action_taken="QUARANTINE",
            incident_id="inc-test-001",
        )


def test_arg_shape_redaction_guarantees():
    """Unit test: verifies compute_arg_shape strips raw secrets and preserves structural keys/lengths."""
    raw = {
        "user_id": 42,
        "token": SECRET_PLANT,
        "is_admin": True,
        "nested": {
            "password": "my_super_secret_password",
            "count": 10,
        },
    }
    shape = compute_arg_shape(raw)
    shape_str = str(shape)

    # 1. The planted secret string must NEVER be present anywhere in the shape
    assert SECRET_PLANT not in shape_str
    assert "my_super_secret_password" not in shape_str

    # 2. Key names and types/lengths must be preserved
    assert shape["type"] == "dict"
    assert "token" in shape["keys"]
    assert shape["keys"]["token"]["type"] == "str"
    assert shape["keys"]["token"]["len"] == len(SECRET_PLANT)
    assert shape["keys"]["user_id"]["type"] == "int"
    assert shape["keys"]["nested"]["keys"]["password"]["len"] == len("my_super_secret_password")


def test_hmac_computed_only_when_key_set():
    """Unit test: HMAC digest is included only when key is configured."""
    # Without key
    s1 = compute_arg_shape("sample_value", hmac_key=None)
    assert "hmac" not in s1
    assert s1["len"] == len("sample_value")

    # With key
    s2 = compute_arg_shape("sample_value", hmac_key="test-secret-salt")
    assert "hmac" in s2
    assert len(s2["hmac"]) == 64  # SHA256 hex


def test_secret_planted_in_payload_never_reaches_action_records(tmp_path):
    """Acceptance test: Plants a secret-like string in an event payload and proves it never reaches action_records."""
    async def _run():
        db_path = str(tmp_path / "test_redaction.db")
        registry = AgentRegistry(db_path)
        await registry.init_db()

        profile = AgentProfile(
            agent_id="customer_bot",
            name="Customer Bot",
            permitted_tools=["search_knowledge_base"],
            permitted_agents=[],
            baseline_call_rate=5.0,
            status=AgentStatus.NORMAL,
        )
        await registry.register_agent(profile)

        detector = MockDetector(score_to_return=0.1)
        executor = MockExecutor()
        event_bus = asyncio.Queue()
        monitor = BehavioralMonitor(registry, detector, executor, event_bus)

        # Plant confidential payload
        event = AgentEvent(
            agent_id="customer_bot",
            event_type=EventType.TOOL_CALL,
            target="search_knowledge_base",
            payload=f'{{"query": "lookup", "confidential_auth": "{SECRET_PLANT}"}}',
            payload_size=100,
            timestamp=time.time(),
            origin="api",
        )

        result = await monitor.observe(event)
        assert result is not None

        # Inspect the raw action_records table in DB
        rows = await registry.db.fetch("SELECT * FROM action_records WHERE agent_id = 'customer_bot'")
        assert len(rows) == 1

        row_dict = dict(rows[0])
        raw_row_text = str(row_dict)

        # STRICT ASSERTION: The planted secret string must NEVER exist in any column
        assert SECRET_PLANT not in raw_row_text, "Planted secret leaked into action_records table!"

        # Verify arg_shape structure
        shape = rows[0]["arg_shape"]
        assert "confidential_auth" in shape
        assert "str" in shape

        await registry.db.close()

    asyncio.run(_run())


def test_high_detector_score_alone_cannot_set_label(tmp_path, monkeypatch):
    """Acceptance test: Proves that a high detector score alone cannot set label ATTACK."""
    async def _run():
        db_path = str(tmp_path / "test_labels.db")
        registry = AgentRegistry(db_path)
        await registry.init_db()

        profile = AgentProfile(
            agent_id="customer_bot",
            name="Customer Bot",
            permitted_tools=["search_knowledge_base"],
            permitted_agents=[],
            baseline_call_rate=5.0,
            status=AgentStatus.NORMAL,
        )
        await registry.register_agent(profile)

        # Critical threat score 0.99
        detector = MockDetector(score_to_return=0.99)
        executor = MockExecutor()
        event_bus = asyncio.Queue()
        monitor = BehavioralMonitor(registry, detector, executor, event_bus)

        # Real operational / external traffic (not simulator ground truth)
        event = AgentEvent(
            agent_id="customer_bot",
            event_type=EventType.TOOL_CALL,
            target="search_knowledge_base",
            payload="select * from users",
            payload_size=20,
            timestamp=time.time(),
            origin="production_gateway",
        )

        obs = await monitor.observe(event)
        assert obs.detection_result.score == 0.99

        # Fetch the recorded ActionRecord
        records = await registry.get_action_records(agent_id="customer_bot")
        assert len(records) == 1
        rec = records[0]

        # Detector score was 0.99, but label MUST NOT be ATTACK!
        # Non-negotiable rule 3: Labels never come from the detector.
        assert rec.label != "ATTACK", f"Violation: Detector score set label to {rec.label}!"
        assert rec.label == "BENIGN_ASSUMED"
        assert rec.label_source == "none"

        # Now verify that human confirmation via POST /incidents/{id}/confirm updates label
        app.state.registry = registry
        app.state.event_bus = asyncio.Queue()
        app.state.monitor = monitor
        app.state.executor = executor

        # Log incident associated with this event
        incident = IncidentRecord(
            incident_id="inc-test-001",
            agent_id="customer_bot",
            threat_type=ThreatType.PROMPT_INJECTION,
            detection_result=obs.detection_result,
            policy_decision=PolicyDecision.DENIED,
            action_taken="QUARANTINE",
            explanation="Confirmed threat",
            event=event,
            timestamp=rec.ts,
        )
        await registry.log_incident(incident)

        # Call endpoint with operator key
        monkeypatch.setattr(
            security,
            "settings",
            SimpleNamespace(operator_api_key=OP_KEY, containment_secret="cs-test-secret"),
        )
        client = TestClient(app)
        res = client.post(
            "/incidents/inc-test-001/confirm",
            headers={"X-VIGIL-Operator-Key": OP_KEY},
        )
        assert res.status_code == 200
        res_data = res.json()
        assert res_data["status"] == "confirmed"
        assert res_data["label"] == "ATTACK"
        assert res_data["label_source"] == "incident_confirmed"

        # Verify action_records now reflects human-confirmed label
        updated_records = await registry.get_action_records(agent_id="customer_bot")
        assert updated_records[0].label == "ATTACK"
        assert updated_records[0].label_source == "incident_confirmed"

        await registry.db.close()

    asyncio.run(_run())


def test_ingest_20000_records_finishes_under_30_seconds(tmp_path):
    """Acceptance test: Ingesting 20,000 records finishes in under 30 seconds."""
    async def _run():
        db_path = str(tmp_path / "test_benchmark.db")
        registry = AgentRegistry(db_path)
        await registry.init_db()

        # Generate 20,000 benign records + 6 attack families (50 attacks each = 300)
        records = generate_action_records(num_benign=20000, attacks_per_family=50)
        total_records = len(records)
        assert total_records >= 20300

        # Benchmark ingestion time
        t_start = time.perf_counter()
        await registry.log_action_records_batch(records)
        t_end = time.perf_counter()

        elapsed = t_end - t_start
        print(f"\n[Benchmark] Ingested {total_records} records in {elapsed:.3f} seconds.")

        # Must complete in under 30 seconds
        assert elapsed < 30.0, f"Ingestion took {elapsed:.2f}s, exceeding 30.0s threshold!"

        # Verify row counts in DB
        row = await registry.db.fetchrow("SELECT COUNT(*) as count FROM action_records")
        assert row["count"] == total_records

        # Query with index verification
        benign_rows = await registry.db.fetchrow("SELECT COUNT(*) as count FROM action_records WHERE label = 'BENIGN_ASSUMED'")
        attack_rows = await registry.db.fetchrow("SELECT COUNT(*) as count FROM action_records WHERE label = 'ATTACK'")
        assert benign_rows["count"] == 20000
        assert attack_rows["count"] == 300

        await registry.db.close()

    asyncio.run(_run())


def test_trace_export_jsonl(tmp_path):
    """Verifies that scripts/trace_export.py exports valid JSONL adhering to schema v1."""
    async def _run():
        import json
        from scripts.trace_export import export_traces

        db_path = str(tmp_path / "test_export.db")
        jsonl_path = str(tmp_path / "exported_traces.jsonl")
        registry = AgentRegistry(db_path)
        await registry.init_db()

        records = generate_action_records(num_benign=100, attacks_per_family=10)
        await registry.log_action_records_batch(records)
        await registry.db.close()

        count = await export_traces(
            db_path=db_path,
            output_path=jsonl_path,
        )
        assert count == 160  # 100 benign + 60 attacks
        assert os.path.exists(jsonl_path)

        with open(jsonl_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        assert len(lines) == 160
        first = lines[0]
        # Schema v1 validation
        required_fields = {
            "record_id", "trace_id", "tenant_id", "agent_id", "ts",
            "mcp_id", "tool", "event_type", "arg_shape", "provenance",
            "prev_tool", "observed_decision", "label", "label_source", "incident_id"
        }
        assert required_fields.issubset(first.keys())
        assert first["label"] in ("BENIGN_ASSUMED", "ATTACK", "UNLABELLED")
        assert isinstance(first["arg_shape"], dict)

    asyncio.run(_run())
