"""Architectural and unit test suite ensuring all agent containment routes strictly through the ArmorIQ gate.

P0-0 Enforcement:
1. Allowlist test: Verifies that ONLY the gate-approved containment callback (main.py:internal_quarantine)
   and the authorized executor applicator (remediation.py:_execute_quarantine) may write status QUARANTINED.
2. Attack graph test: Verifies attack_graph_service creates approval requests instead of writing status directly.
3. Auto-remediation test: Verifies auto-remediation requests containment through the gate rather than writing status.
4. Ledger source test: Verifies every containment records its source ('gate', 'human', 'auto', 'graph') in the audit ledger.
"""

import ast
import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import pytest

from backend.app.runtime.models import (
    AgentEvent,
    EventType,
    AgentProfile,
    AgentStatus,
    ApprovalRequest,
    ApprovalStatus,
    AttackGraphEdge,
    AttackGraphNode,
    DetectionResult,
    IncidentRecord,
    PolicyDecision,
    ThreatType,
    Confidence,
)
from backend.app.runtime.ledger import AuditLedger
from backend.services.attack_graph_service import AttackGraphService
from backend.services.auto_remediation_orchestrator import AutoRemediationOrchestrator


def test_quarantine_status_allowlist():
    """Scans the backend codebase to ensure NO unauthorized module sets AgentStatus.QUARANTINED."""
    backend_root = Path(__file__).resolve().parent.parent
    violations = []
    
    # Authorized call-sites allowed to apply QUARANTINED status:
    # 1. backend/main.py -> internal_quarantine (the gate-approved containment callback)
    # 2. backend/app/remediation/remediation.py -> _execute_quarantine (remediation applicator when gate approves)
    allowed_rel_paths = {
        "main.py",
        "app/remediation/remediation.py",
    }
    
    forbidden_files = {
        "services/attack_graph_service.py",
        "services/auto_remediation_orchestrator.py",
        "services/quarantine_service.py",
        "app/runtime/simulator.py",
    }

    for py_file in backend_root.rglob("*.py"):
        rel = py_file.relative_to(backend_root).as_posix()
        # Skip tests and archive
        if rel.startswith("tests/") or "archive" in rel:
            continue
            
        with open(py_file, "r", encoding="utf-8") as f:
            source = f.read()
            
        tree = ast.parse(source, filename=str(py_file))
        
        for node in ast.walk(tree):
            # Check for: agent.status = AgentStatus.QUARANTINED or .status = 'QUARANTINED'
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "status":
                        # Check value being assigned
                        val = node.value
                        is_quarantined = False
                        if isinstance(val, ast.Attribute) and val.attr == "QUARANTINED":
                            is_quarantined = True
                        elif isinstance(val, ast.Constant) and val.value == "QUARANTINED":
                            is_quarantined = True
                        
                        if is_quarantined and rel not in allowed_rel_paths:
                            violations.append((rel, node.lineno, "assignment to .status = QUARANTINED"))
            
            # Check for: update_status(..., AgentStatus.QUARANTINED) or update_status(..., 'QUARANTINED')
            if isinstance(node, ast.Call):
                func = node.func
                is_update_status = False
                if isinstance(func, ast.Attribute) and func.attr == "update_status":
                    is_update_status = True
                elif isinstance(func, ast.Name) and func.id == "update_status":
                    is_update_status = True
                    
                if is_update_status:
                    # Exclude the definition inside AgentRegistry class itself
                    for arg in node.args:
                        is_quarantine_arg = False
                        if isinstance(arg, ast.Attribute) and arg.attr == "QUARANTINED":
                            is_quarantine_arg = True
                        elif isinstance(arg, ast.Constant) and arg.value == "QUARANTINED":
                            is_quarantine_arg = True
                            
                        if is_quarantine_arg and rel not in allowed_rel_paths:
                            violations.append((rel, node.lineno, "call to update_status with QUARANTINED"))

    # Explicitly check forbidden files
    for rel_path, lineno, reason in violations:
        for forbidden in forbidden_files:
            assert forbidden not in rel_path, f"Forbidden file {rel_path}:{lineno} writes status QUARANTINED: {reason}"

    assert len(violations) == 0, f"Found unauthorized QUARANTINED status writes: {violations}"


def test_attack_graph_creates_approval_requests_not_quarantine():
    """AttackGraphService must create ApprovalRequest records, never write status QUARANTINED directly."""
    async def _test():
        created_requests = []
        registered_agents = []
        
        class FakeRegistry:
            async def get_attack_graph_edges(self):
                return [
                    AttackGraphEdge(
                        edge_id="e1",
                        source_agent_id="attacker",
                        target_agent_id="victim",
                        propagation_probability=0.95,
                        delegation_count=5,
                    )
                ]

            async def get_attack_graph_nodes(self):
                return []

            async def save_attack_graph_node(self, node):
                pass

            async def get_agent(self, agent_id):
                if agent_id == "victim":
                    return AgentProfile(
                        agent_id="victim",
                        name="Victim Bot",
                        permitted_tools=[],
                        permitted_agents=[],
                        baseline_call_rate=1.0,
                        status=AgentStatus.NORMAL,
                    )
                return None

            async def register_agent(self, agent):
                registered_agents.append(agent)

            async def create_approval_request(self, request: ApprovalRequest):
                created_requests.append(request)

        registry = FakeRegistry()
        service = AttackGraphService(registry)
        
        # Run attack chain isolation
        affected = await service.isolate_attack_chain("attacker")
        
        # Assert victim was flagged for approval, NOT modified in registry directly
        assert "victim" in affected
        assert len(created_requests) == 1
        assert created_requests[0].agent_id == "victim"
        assert created_requests[0].proposed_action == "QUARANTINE"
        assert created_requests[0].status == ApprovalStatus.PENDING
        assert len(registered_agents) == 0  # register_agent was NOT called with status QUARANTINED

    asyncio.run(_test())


def test_auto_remediation_requests_containment_through_gate():
    """AutoRemediationOrchestrator must request containment from executor, not write status directly."""
    async def _test():
        saved_chains = []
        requested_containments = []
        
        class FakeRegistry:
            async def save_remediation_chain(self, chain):
                saved_chains.append(chain)

        class FakeExecutor:
            async def request_containment(self, agent_id, threat_type, score, source="gate", incident_id=None):
                requested_containments.append({
                    "agent_id": agent_id,
                    "threat_type": threat_type,
                    "score": score,
                    "source": source,
                    "incident_id": incident_id,
                })
                return "QUARANTINE"

        registry = FakeRegistry()
        executor = FakeExecutor()
        orchestrator = AutoRemediationOrchestrator(registry, executor=executor)
        
        # Trigger incident response
        chain_id = await orchestrator.execute_incident_response(
            incident_id="inc-123",
            agent_id="target-bot",
            threat_type="PRIVILEGE_ESCALATION",
        )
        
        # Wait for background pipeline to reach step 1 (uses 1s sleep per step)
        await asyncio.sleep(2.5)
        
        # Assert containment was requested through executor with source='auto'
        assert len(requested_containments) >= 1
        req = requested_containments[0]
        assert req["agent_id"] == "target-bot"
        assert req["source"] == "auto"
        assert req["incident_id"] == "inc-123"

    asyncio.run(_test())


def test_containment_ledger_records_source(tmp_path):
    """Every containment action must record its origin source in the audit ledger."""
    async def _test():
        ledger_path = tmp_path / "test_ledger.jsonl"
        ledger = AuditLedger(ledger_path)
        
        class FakeGate:
            def __init__(self):
                self.mode = "local-demo"
                self.ledger = ledger
                
            async def authorize_containment(self, ctx, human_approved=False):
                return PolicyDecision.APPROVED
                
            async def log_audit(self, ctx, decision, action, source="gate"):
                self.ledger.append({
                    "agent_id": ctx.agent_id,
                    "action": action,
                    "decision": decision.value,
                    "source": source,
                    "score": ctx.score,
                })

        from backend.app.remediation.remediation import RemediationExecutor
        
        statuses = {}
        class FakeRegistry:
            async def update_status(self, agent_id, status, source=None):
                statuses[agent_id] = (status, source)
            async def get_agent(self, agent_id):
                return SimpleNamespace(model_dump=lambda mode="json": {"agent_id": agent_id})
            async def log_incident(self, inc):
                pass

        gate = FakeGate()
        registry = FakeRegistry()
        event_bus = asyncio.Queue()
        explainer = SimpleNamespace()
        
        executor = RemediationExecutor(registry, gate, event_bus, explainer)
        
        # 1. Test auto source
        outcome_auto = await executor.request_containment(
            agent_id="bot_auto",
            threat_type=ThreatType.UNAUTHORIZED_DELEGATION,
            score=0.91,
            source="auto",
        )
        assert outcome_auto == "QUARANTINE"
        assert statuses["bot_auto"] == (AgentStatus.QUARANTINED, "auto")
        
        # 2. Test human source
        incident = IncidentRecord(
            incident_id="inc-h1",
            agent_id="bot_human",
            threat_type=ThreatType.PROMPT_INJECTION,
            detection_result=DetectionResult(
                score=0.92,
                threat_type=ThreatType.PROMPT_INJECTION,
                confidence=Confidence.HIGH,
                rule_score=0.9,
                ewma_score=0.9,
                iforest_score=0.9,
            ),
            policy_decision=PolicyDecision.ESCALATE,
            action_taken="AWAITING_APPROVAL",
            explanation="",
            timestamp=100.0,
            event=AgentEvent(
                agent_id="bot_human",
                event_type=EventType.TOOL_CALL,
                target="db",
                payload="test",
                payload_size=10,
            ),
        )
        outcome_human = await executor.execute_human_approved(incident, "QUARANTINE", approver="admin")
        assert outcome_human == "QUARANTINE"
        assert statuses["bot_human"] == (AgentStatus.QUARANTINED, "human")
        
        # Verify ledger entries
        res = ledger.verify()
        assert res.ok is True
        assert res.entries == 2
        
        import json
        with open(ledger_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
            
        assert lines[0]["record"]["source"] == "auto"
        assert lines[0]["record"]["agent_id"] == "bot_auto"
        assert lines[1]["record"]["source"] == "human"
        assert lines[1]["record"]["agent_id"] == "bot_human"

    asyncio.run(_test())
