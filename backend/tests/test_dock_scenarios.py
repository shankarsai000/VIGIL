"""Tests for P1-1: Ensure each dock scenario produces a detection (score >= 0.45) in local-demo mode."""
import asyncio
import pytest
from unittest.mock import AsyncMock

from backend.app.config import settings
from backend.app.runtime.threat_sim import ATTACK_SCENARIOS, get_attack_event
from backend.app.runtime.registry import AgentRegistry
from backend.app.runtime.seed import DEMO_AGENTS
from backend.app.detection.detector import HybridDetector
from backend.app.remediation.remediation import RemediationExecutor
from backend.app.telemetry.monitor import BehavioralMonitor
from backend.app.policies.armoriq_gate import ArmorIQGate
from backend.app.explainability.explainer import VIGILExplainer
from backend.services.prompt_mutation_service import PromptMutationService
from backend.services.capability_enforcer_service import CapabilityEnforcerService
from backend.services.behavioral_spoofing_service import BehavioralSpoofingService

DOCK_SCENARIOS = [
    "prompt_injection",
    "privilege_escalation",
    "unauthorized_delegation",
    "data_exfiltration",
    "rate_anomaly",
    "model_integrity_drift",
    "prompt_mutation",
    "capability_violation",
    "supply_chain_tamper",
    "behavioral_spoofing",
]


@pytest.mark.parametrize("scenario_name", DOCK_SCENARIOS)
def test_dock_scenario_produces_detection_in_local_demo(scenario_name, monkeypatch, tmp_path):
    async def _run():
        monkeypatch.setattr(settings, "armoriq_mode", "local-demo")

        db_file = tmp_path / f"test_{scenario_name}.db"
        registry = AgentRegistry(str(db_file))
        await registry.init_db()

        for agent in DEMO_AGENTS:
            await registry.register_agent(agent)

        gate = ArmorIQGate(settings, registry)
        detector = HybridDetector(settings)
        explainer = VIGILExplainer(config=settings)

        class DummyBus:
            async def put(self, ev):
                pass

        bus = DummyBus()
        executor = RemediationExecutor(registry, gate, bus, explainer)

        pm_service = PromptMutationService(registry)
        cap_service = CapabilityEnforcerService(registry)
        spoof_service = BehavioralSpoofingService(registry)

        monitor = BehavioralMonitor(
            registry=registry,
            detector=detector,
            executor=executor,
            event_bus=bus,
            prompt_mutation_service=pm_service,
            capability_enforcer_service=cap_service,
            behavioral_spoofing_service=spoof_service,
        )

        event = get_attack_event(scenario_name)
        observation = await monitor.observe(event)

        assert observation is not None, f"Observation for {scenario_name} was None"
        assert observation.detection_result is not None, f"DetectionResult for {scenario_name} was None"
        assert (
            observation.detection_result.score >= 0.45
        ), f"Scenario '{scenario_name}' scored {observation.detection_result.score:.2f}, expected >= 0.45"
        assert (
            observation.action_taken is not None
        ), f"Scenario '{scenario_name}' did not trigger an action (action_taken was None)"

        await registry.db.close()

    asyncio.run(_run())
