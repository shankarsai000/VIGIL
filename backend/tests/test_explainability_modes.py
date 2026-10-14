"""Tests for P0-5: Honest narrative in ExplainabilityService for each mode and storage."""
from types import SimpleNamespace
import pytest

from backend.app.config import settings
from backend.app.runtime.models import PolicyDecision, ThreatType
from backend.services.explainability_service import explainability_service, get_storage_name


def _create_mock_incident(score: float = 0.90, decision: PolicyDecision = PolicyDecision.APPROVED, action: str = "LOG"):
    return SimpleNamespace(
        agent_id="customer_bot",
        threat_type=ThreatType.PROMPT_INJECTION,
        detection_result=SimpleNamespace(score=score),
        policy_decision=decision,
        action_taken=action,
        timestamp=1700000000.123,
        event=SimpleNamespace(target="user_input", payload="test prompt"),
    )


def test_storage_name_reads_from_config(monkeypatch):
    # Test PostgreSQL
    monkeypatch.setattr(settings, "database_url", "postgresql://user:pass@localhost:5432/vigil")
    assert get_storage_name() == "PostgreSQL"

    # Test SQLite
    monkeypatch.setattr(settings, "database_url", "sqlite:///vigil.db")
    assert get_storage_name() == "SQLite"


def test_narrative_sentence_3_uses_configured_storage(monkeypatch):
    monkeypatch.setattr(settings, "database_url", "postgresql://user:pass@localhost:5432/vigil")
    incident = _create_mock_incident(action="LOG")
    explanation = explainability_service.generate_rule_based(incident, enforcement="local-demo")
    assert "logged to PostgreSQL" in explanation
    assert "logged to SQLite" not in explanation


def test_armoriq_live_mode_says_armoriq_approved():
    incident = _create_mock_incident(decision=PolicyDecision.APPROVED)
    explanation = explainability_service.generate_rule_based(incident, enforcement="armoriq-live")
    assert "ArmorIQ approved the containment response." in explanation

    explanation_live = explainability_service.generate_rule_based(incident, enforcement="live")
    assert "ArmorIQ approved the containment response." in explanation_live


def test_local_demo_mode_never_claims_armoriq_approved():
    incident = _create_mock_incident(decision=PolicyDecision.APPROVED)
    explanation = explainability_service.generate_rule_based(incident, enforcement="local-demo")
    assert "ArmorIQ approved" not in explanation
    assert "local demo thresholds approved the containment response (not ArmorIQ enforced)" in explanation


def test_disabled_mode_reports_disabled_containment():
    incident = _create_mock_incident(decision=PolicyDecision.APPROVED)
    explanation = explainability_service.generate_rule_based(incident, enforcement="disabled")
    assert "ArmorIQ approved" not in explanation
    assert "containment was disabled by configuration policy" in explanation
