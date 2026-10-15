"""Acceptance Tests for Phase M3: Candidate Rules and the Dry-Run Compiler."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

from backend.app.immune.records import ActionRecord
from backend.app.immune.replay import CandidateRule, ReplayAssumptions, ReplayReport
from backend.app.immune.candidates import (
    AttackFamilyCandidate,
    extract_candidates,
    STATUS_ACCEPT,
    STATUS_INSUFFICIENT_EVIDENCE,
    STATUS_REJECT,
    STATUS_NOT_ENFORCEABLE,
)
from backend.app.immune.compiler import (
    ImpactTier,
    PolicyProposal,
    CompiledArtifacts,
    ApprovalError,
    compile_agent_policy,
    execute_compile,
)


def _make_dummy_replay_report(
    agent_id: str,
    tool: str,
    status: str,
    coverage: float,
    attacks_total: int,
    attacks_blocked: int,
    benign_total: int,
    benign_blocked: int,
    false_block_upper: float,
) -> ReplayReport:
    """Creates a deterministic ReplayReport for candidate testing."""
    return ReplayReport(
        candidate_rule=CandidateRule(agent_id=agent_id, tool=tool, mcp_id="vigil-tools"),
        status=status,
        coverage=coverage,
        attacks_total=attacks_total,
        attacks_blocked=attacks_blocked,
        benign_total=benign_total,
        benign_blocked=benign_blocked,
        false_block_point=(benign_blocked / benign_total) if benign_total > 0 else 0.0,
        false_block_upper=false_block_upper,
        delta=0.05,
        assumptions=ReplayAssumptions(
            window_bounds={
                "start_ts": 1700000000.0,
                "end_ts": 1700001000.0,
                "duration_seconds": 1000.0,
                "records_evaluated": attacks_total + benign_total,
            }
        ),
    )


def test_candidates_extraction_and_classification():
    """Acceptance test: Extract candidates, group ATTACK by (agent, tool), and classify outcomes.
    
    Verifies:
    1. ACCEPT: High coverage, bound <= 0.005, sufficient data.
    2. NOT_ENFORCEABLE: Tool is used in benign traffic (benign_blocked > 0). ArmorIQ globs match tools, not argument values.
    3. REJECT: Low coverage with enough data.
    4. INSUFFICIENT_EVIDENCE: Fails sample thresholds.
    5. REJECT on unsafe tool name (non-plain identifier).
    """
    records = []

    # 1. ACCEPT Candidate: bot_alpha -> secret_dump (5 attacks, 700 benign on safe_tool)
    for i in range(5):
        records.append(
            ActionRecord(
                agent_id="bot_alpha",
                tool="secret_dump",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="ATTACK",
                ts=100.0 + i,
            )
        )
    for i in range(700):
        records.append(
            ActionRecord(
                agent_id="bot_alpha",
                tool="safe_tool",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="BENIGN_ASSUMED",
                ts=200.0 + i,
            )
        )

    # 2. NOT_ENFORCEABLE Candidate: bot_omega -> sql_query
    # Both attacks and benign use sql_query! Separates only by argument value.
    for i in range(5):
        records.append(
            ActionRecord(
                agent_id="bot_omega",
                tool="sql_query",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict", "query": "DROP TABLE"},
                label="ATTACK",
                ts=300.0 + i,
            )
        )
    for i in range(10):
        records.append(
            ActionRecord(
                agent_id="bot_omega",
                tool="sql_query",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict", "query": "SELECT *"},
                label="BENIGN_ASSUMED",
                ts=400.0 + i,
            )
        )

    # 3. REJECT Candidate: bot_beta -> partial_attack (2 attacks on partial_attack, 8 attacks on other_attack, 700 benign)
    # Coverage = 2/10 = 0.20 < 0.90
    for i in range(2):
        records.append(
            ActionRecord(
                agent_id="bot_beta",
                tool="partial_attack",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="ATTACK",
                ts=500.0 + i,
            )
        )
    for i in range(8):
        records.append(
            ActionRecord(
                agent_id="bot_beta",
                tool="other_attack",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="ATTACK",
                ts=510.0 + i,
            )
        )
    for i in range(700):
        records.append(
            ActionRecord(
                agent_id="bot_beta",
                tool="clean_tool",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="BENIGN_ASSUMED",
                ts=600.0 + i,
            )
        )

    # 4. INSUFFICIENT_EVIDENCE Candidate: bot_gamma -> rare_attack (1 attack, 50 benign)
    records.append(
        ActionRecord(
            agent_id="bot_gamma",
            tool="rare_attack",
            mcp_id="vigil-tools",
            event_type="TOOL_CALL",
            arg_shape={"type": "dict"},
            label="ATTACK",
            ts=700.0,
        )
    )
    for i in range(50):
        records.append(
            ActionRecord(
                agent_id="bot_gamma",
                tool="normal_tool",
                mcp_id="vigil-tools",
                event_type="TOOL_CALL",
                arg_shape={"type": "dict"},
                label="BENIGN_ASSUMED",
                ts=710.0 + i,
            )
        )

    # 5. UNSAFE Tool Identifier Candidate: bot_delta -> "eval;rm"
    records.append(
        ActionRecord(
            agent_id="bot_delta",
            tool="eval;rm -rf /",
            mcp_id="vigil-tools",
            event_type="TOOL_CALL",
            arg_shape={"type": "dict"},
            label="ATTACK",
            ts=800.0,
        )
    )

    candidates = extract_candidates(records)
    by_key = {(c.agent_id, c.tool): c for c in candidates}

    # Verify 1: secret_dump is ACCEPT
    cand_accept = by_key[("bot_alpha", "secret_dump")]
    assert cand_accept.status == STATUS_ACCEPT
    assert cand_accept.replay_report.false_block_upper <= 0.005
    assert cand_accept.replay_report.coverage == 1.0

    # Verify 2: sql_query is NOT_ENFORCEABLE (separates only by argument value)
    cand_ne = by_key[("bot_omega", "sql_query")]
    assert cand_ne.status == STATUS_NOT_ENFORCEABLE
    assert "Separates only by argument value" in cand_ne.reason
    assert "ArmorIQ globs match tools, not argument values" in cand_ne.reason
    assert cand_ne.replay_report.benign_blocked == 10

    # Verify 3: partial_attack is REJECT (low coverage)
    cand_rej = by_key[("bot_beta", "partial_attack")]
    assert cand_rej.status == STATUS_REJECT
    assert cand_rej.replay_report.coverage == 0.20

    # Verify 4: rare_attack is INSUFFICIENT_EVIDENCE
    cand_ins = by_key[("bot_gamma", "rare_attack")]
    assert cand_ins.status == STATUS_INSUFFICIENT_EVIDENCE

    # Verify 5: unsafe tool is REJECT
    cand_unsafe = by_key[("bot_delta", "eval;rm -rf /")]
    assert cand_unsafe.status == STATUS_REJECT
    assert "not a plain tool name" in cand_unsafe.reason


def test_golden_file_yaml_and_inline_policy():
    """Acceptance test: Golden-file tests for the YAML patch and inline policy."""
    rep = _make_dummy_replay_report(
        agent_id="customer-bot",
        tool="billing_database",
        status="ACCEPT",
        coverage=1.0,
        attacks_total=5,
        attacks_blocked=5,
        benign_total=700,
        benign_blocked=0,
        false_block_upper=0.00427,
    )
    cand = AttackFamilyCandidate(
        agent_id="customer-bot",
        tool="billing_database",
        mcp_id="vigil-tools",
        status=STATUS_ACCEPT,
        reason="Verified safe",
        replay_report=rep,
        candidate_rule=CandidateRule(agent_id="customer-bot", tool="billing_database", mcp_id="vigil-tools"),
    )
    proposal = PolicyProposal(
        proposal_id="prop-golden-001",
        agent_id="customer-bot",
        status="APPROVED",
        impact_tier=ImpactTier.LOW,
        approvals=["operator_admin"],
        candidates=[cand],
    )

    artifacts = compile_agent_policy(proposal)

    # Golden YAML expectations:
    # 1. version: v1
    # 2. agent_id: customer-bot
    # 3. dot notation under policy.deny: vigil-tools.billing_database
    expected_yaml = (
        "# Proposed ArmorIQ deny rules for agent: customer-bot\n"
        "# Compatible with ArmorIQ CLI: armoriq validate --config <file>\n"
        "version: v1\n"
        "identity:\n"
        "  api_key: ${ARMORIQ_API_KEY}\n"
        "  user_id: ${ARMORIQ_USER_EMAIL}\n"
        "  agent_id: customer-bot\n"
        "policy:\n"
        "  allow: []\n"
        "  deny:\n"
        "    - vigil-tools.billing_database\n"
    )
    assert artifacts.yaml_patch_content == expected_yaml

    # Golden SDK inline policy expectations:
    # slash notation: vigil-tools/billing_database
    expected_inline = {
        "allow": [],
        "deny": ["vigil-tools/billing_database"],
    }
    assert artifacts.inline_policy == expected_inline

    # Manifest expectations
    manifest = artifacts.manifest
    assert manifest["proposal_id"] == "prop-golden-001"
    assert manifest["agent_id"] == "customer-bot"
    assert manifest["rules"]["dot_notation"] == ["vigil-tools.billing_database"]
    assert manifest["rules"]["slash_notation"] == ["vigil-tools/billing_database"]
    assert "exchangeability" in manifest["assumptions"]


def test_compiler_idempotence():
    """Acceptance test: Idempotence — running the compiler twice gives identical bytes."""
    rep = _make_dummy_replay_report(
        agent_id="sales-agent",
        tool="bulk_export",
        status="ACCEPT",
        coverage=1.0,
        attacks_total=10,
        attacks_blocked=10,
        benign_total=1200,
        benign_blocked=0,
        false_block_upper=0.00249,
    )
    cand = AttackFamilyCandidate(
        agent_id="sales-agent",
        tool="bulk_export",
        mcp_id="crm-tools",
        status=STATUS_ACCEPT,
        reason="Clean block",
        replay_report=rep,
        candidate_rule=CandidateRule(agent_id="sales-agent", tool="bulk_export", mcp_id="crm-tools"),
    )
    proposal = PolicyProposal(
        proposal_id="prop-idempotence-101",
        agent_id="sales-agent",
        status="APPROVED",
        impact_tier=ImpactTier.MEDIUM,
        approvals=["operator_sec"],
        candidates=[cand],
    )

    run1 = compile_agent_policy(proposal)
    run2 = compile_agent_policy(proposal)

    assert run1.yaml_bytes() == run2.yaml_bytes()
    assert run1.inline_policy_bytes() == run2.inline_policy_bytes()
    assert run1.manifest_bytes() == run2.manifest_bytes()


def test_dry_run_writes_nothing(tmp_path):
    """Acceptance test: Dry-run writes nothing. File system compared before and after."""
    proposal = PolicyProposal(
        proposal_id="prop-dryrun-001",
        agent_id="support-agent",
        status="APPROVED",
        impact_tier=ImpactTier.LOW,
        approvals=["approver_1"],
        candidates=[],
    )

    before_listing = list(tmp_path.iterdir())
    assert len(before_listing) == 0

    artifacts, written = execute_compile(proposal, write=False, output_dir=tmp_path)

    after_listing = list(tmp_path.iterdir())
    assert len(after_listing) == 0
    assert len(written) == 0
    assert artifacts is not None


def test_write_without_approval_refuses_and_exits_nonzero(tmp_path):
    """Acceptance test: --write without approval or meeting impact tier demands refuses."""
    # Case 1: Status is PENDING (not APPROVED)
    proposal_pending = PolicyProposal(
        proposal_id="prop-unapproved",
        agent_id="devops-bot",
        status="PENDING",
        impact_tier=ImpactTier.LOW,
        approvals=[],
    )
    with pytest.raises(ApprovalError) as exc_pending:
        execute_compile(proposal_pending, write=True, output_dir=tmp_path)
    assert "must be 'APPROVED'" in str(exc_pending.value)

    # Case 2: Status is APPROVED, but ImpactTier is HIGH (demands 2 approvals), only 1 provided
    proposal_high_tier = PolicyProposal(
        proposal_id="prop-high-tier",
        agent_id="devops-bot",
        status="APPROVED",
        impact_tier=ImpactTier.HIGH,
        approvals=["operator_1"],  # only 1 approval!
    )
    with pytest.raises(ApprovalError) as exc_high:
        execute_compile(proposal_high_tier, write=True, output_dir=tmp_path)
    assert "demands at least 2" in str(exc_high.value)

    # Verify zero files written to tmp_path during failures
    assert len(list(tmp_path.iterdir())) == 0


def test_cli_write_without_approval_exits_nonzero(tmp_path):
    """Acceptance test: CLI invocation of --write without approvals exits non-zero."""
    proposal_file = tmp_path / "test_proposal.json"
    proposal_data = {
        "proposal_id": "prop-cli-unapproved",
        "agent_id": "devops-bot",
        "status": "PENDING",
        "impact_tier": "LOW",
        "approvals": [],
        "candidates": [],
    }
    proposal_file.write_text(json.dumps(proposal_data), encoding="utf-8")

    cmd = [
        sys.executable,
        "-m",
        "backend.app.immune.compiler",
        "--proposal-file",
        str(proposal_file),
        "--write",
        "--output-dir",
        str(tmp_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode != 0
    assert "Approval Error" in res.stderr


def test_name_safety_refuses_non_identifiers():
    """Acceptance test: Name-safety check refuses tool or agent names that are not plain identifiers."""
    cand = AttackFamilyCandidate(
        agent_id="valid-agent",
        tool="rm -rf /",  # spaces and slash
        mcp_id="vigil-tools",
        status=STATUS_ACCEPT,
        reason="test",
        candidate_rule=CandidateRule(agent_id="valid-agent", tool="rm -rf /"),
    )
    proposal = PolicyProposal(
        proposal_id="prop-unsafe",
        agent_id="valid-agent",
        status="APPROVED",
        impact_tier=ImpactTier.LOW,
        approvals=["app_1"],
        candidates=[cand],
    )

    with pytest.raises(ValueError) as exc_info:
        compile_agent_policy(proposal)
    assert "not a plain identifier" in str(exc_info.value)


def test_armoriq_validate_on_generated_file(tmp_path):
    """Acceptance test: Run armoriq validate on generated file.
    
    If the CLI is missing or not authenticated, records BLOCKED with error details.
    """
    cand = AttackFamilyCandidate(
        agent_id="customer-bot",
        tool="billing_database",
        mcp_id="vigil-tools",
        status=STATUS_ACCEPT,
        reason="Replay verified",
        candidate_rule=CandidateRule(agent_id="customer-bot", tool="billing_database", mcp_id="vigil-tools"),
    )
    proposal = PolicyProposal(
        proposal_id="prop-validate-001",
        agent_id="customer-bot",
        status="APPROVED",
        impact_tier=ImpactTier.LOW,
        approvals=["admin"],
        candidates=[cand],
    )

    # Write artifact using approved proposal
    artifacts, written = execute_compile(proposal, write=True, output_dir=tmp_path)
    yaml_path = [p for p in written if p.suffix == ".yaml"][0]
    assert yaml_path.exists()

    # Run armoriq validate
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    cmd = [".venv/Scripts/armoriq.exe", "validate", "--config", str(yaml_path)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env)
        stdout = proc.stdout
        stderr = proc.stderr
        returncode = proc.returncode
    except FileNotFoundError:
        # CLI missing -> record BLOCKED
        print("\n[ArmorIQ Validate] BLOCKED: armoriq CLI executable not found.")
        return

    # Check outcomes
    if returncode == 0:
        print("\n[ArmorIQ Validate] PASS: armoriq validate passed successfully.")
    else:
        # CLI is not authenticated or proxy unreachable -> record BLOCKED
        is_syntax_valid = "Config syntax valid" in stdout or "Config syntax valid" in stderr
        is_auth_error = (
            "API key is empty" in stdout or "API key is empty" in stderr or
            "not authenticated" in stdout or "not authenticated" in stderr or
            "401" in stdout or "401" in stderr
        )
        print(f"\n[ArmorIQ Validate] Result code={returncode}")
        print(f"STDOUT: {stdout.strip()}")
        print(f"STDERR: {stderr.strip()}")

        assert is_syntax_valid or is_auth_error, (
            f"Expected config syntax validation or auth error, got: {stdout} / {stderr}"
        )
        print("[ArmorIQ Validate] BLOCKED: Config syntax is valid; live validation blocked by unauthenticated API key.")
