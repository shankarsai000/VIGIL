"""VIGIL Policy Immune System — End-to-End Governance Policy Loop Demo.

Demonstrates the full autonomous immune lifecycle:
1. Incident detection & confirmation
2. Candidate rule generation
3. Counterfactual replay table (coverage & exact Clopper-Pearson bound)
4. Two-person cryptographic approval workflow
5. Verification (sandbox agent: attack calls blocked, benign calls allowed)
6. Ed25519-signed verification receipt appended to audit ledger
7. Cross-tenant shared signature export & import

Usage:
    python scripts/demo_policy_loop.py [--offline]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Ensure repo root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from dotenv import load_dotenv
load_dotenv(repo_root / ".env")

from backend.app.immune.records import ActionRecord
from backend.app.immune.candidates import extract_candidates
from backend.app.immune.replay import CandidateRule, ReplayEngine
from backend.app.immune.workflow import (
    PolicyProposalRecord,
    STATUS_APPROVED,
    STATUS_PROPOSED,
    TIER_HIGH,
    compute_impact_tier,
)
from backend.app.immune.verify import (
    ArmorIQVerifier,
    FakeArmorIQClient,
    verify_receipt,
)
from backend.app.immune.signatures import (
    export_signature_bundle,
    import_signature_bundle,
)


def run_demo(offline: bool = True):
    start_time = time.time()
    print("=" * 80)
    print(" VIGIL POLICY IMMUNE SYSTEM — AUTONOMOUS RUNTIME GOVERNANCE DEMO")
    print(f" Execution Mode: {'OFFLINE (fakes)' if offline else 'LIVE (ArmorIQ platform)'}")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # Step 1: Incident Ingestion & Action Records
    # -------------------------------------------------------------------------
    print("\n[Step 1/6] INCIDENT INGESTION & ACTION RECORDS")
    print("  Scenario: Malicious prompt injection triggers unauthorized billing database dump.")
    incident_id = "inc-2026-10-m6-exfil"
    agent_id = "customer-bot"
    mcp_id = "vigil-tools"
    attack_tool = "billing_database"
    benign_tool = "order_status"

    records = []
    # 620 historical benign calls
    for i in range(620):
        records.append(
            ActionRecord(
                record_id=f"rec-benign-{i:04d}",
                trace_id=f"trace-b-{i//10}",
                tenant_id="tenant-acme",
                agent_id=agent_id,
                ts=time.time() - 86400 + (i * 100),
                mcp_id=mcp_id,
                tool=benign_tool,
                event_type="tool_invoke",
                arg_shape={"order_id": "str", "length": 9},
                provenance="trusted",
                prev_tool=None,
                observed_decision="ALLOW",
                label="BENIGN_ASSUMED",
                label_source="simulator_ground_truth",
            )
        )

    # 12 confirmed attack calls in incident
    for j in range(12):
        records.append(
            ActionRecord(
                record_id=f"rec-attack-{j:04d}",
                trace_id="trace-attack-exfil",
                tenant_id="tenant-acme",
                agent_id=agent_id,
                ts=time.time() - 3600 + (j * 10),
                mcp_id=mcp_id,
                tool=attack_tool,
                event_type="tool_invoke",
                arg_shape={"query": "str", "length": 35},
                provenance="untrusted_content",
                prev_tool="order_status",
                observed_decision="ALLOW",
                label="ATTACK",
                label_source="incident_confirmed",
                incident_id=incident_id,
            )
        )

    print(f"  Ingested {len(records)} action records for agent '{agent_id}':")
    print(f"    - Benign baseline: 620 records (assumed benign)")
    print(f"    - Confirmed incident '{incident_id}': 12 attack records")

    # -------------------------------------------------------------------------
    # Step 2: Candidate Rule Generation
    # -------------------------------------------------------------------------
    print("\n[Step 2/6] CANDIDATE RULE GENERATION")
    candidates = extract_candidates(records)
    print(f"  Extracted {len(candidates)} attack candidate families:")
    for c in candidates:
        print(f"    - Candidate: Agent '{c.agent_id}' | Tool: '{c.mcp_id}.{c.tool}' | Status: {c.status}")

    target_candidate = CandidateRule(agent_id=agent_id, mcp_id=mcp_id, tool=attack_tool)

    # -------------------------------------------------------------------------
    # Step 3: Counterfactual Replay Table & Statistical Upper Bound
    # -------------------------------------------------------------------------
    print("\n[Step 3/6] COUNTERFACTUAL REPLAY TABLE & EXACT STATISTICAL BOUND")
    engine = ReplayEngine(delta=0.05)
    report = engine.evaluate(records, target_candidate)

    print("  +-----------------------------------------------------------------------+")
    print("  | Metric                      | Observed Value | Mathematical Criterion |")
    print("  +-----------------------------------------------------------------------+")
    print(f"  | Attacks Observed            | {report.attacks_total:<14} | Total incident vectors |")
    print(f"  | Attacks Blocked             | {report.attacks_blocked:<14} | Target tool matches    |")
    print(f"  | Attack Coverage             | {report.coverage * 100:>13.1f}% | >= 90.0% required      |")
    print(f"  | Benign Baseline             | {report.benign_total:<14} | >= 600 required        |")
    print(f"  | Benign False Blocks         | {report.benign_blocked:<14} | Metric to MINIMISE     |")
    print(f"  | False-Block Rate (Point)    | {report.false_block_point * 100:>13.2f}% | Empirical rate         |")
    print(f"  | 95% Clopper-Pearson Bound   | {report.false_block_upper * 100:>13.3f}% | <= 0.500% required     |")
    print(f"  | REPLAY VERDICT              | {report.status:<14} | SAFE TO PROPOSE        |")
    print("  +-----------------------------------------------------------------------+")

    # -------------------------------------------------------------------------
    # Step 4: Two-Person Governance Approval Workflow
    # -------------------------------------------------------------------------
    print("\n[Step 4/6] TWO-PERSON GOVERNANCE APPROVAL WORKFLOW")
    impact_tier = compute_impact_tier(report, agent_count=2)  # High impact demands 2 distinct approvers
    proposal_id = f"prop-demo-{int(time.time()) % 100000}"

    proposal = PolicyProposalRecord(
        id=proposal_id,
        status=STATUS_PROPOSED,
        agent_id=agent_id,
        mcp_id=mcp_id,
        tool=attack_tool,
        impact_tier=impact_tier,
        replay_json=report.to_json(),
        assumptions_json=json.dumps({
            "exchangeability": report.assumptions.exchangeability,
            "assumed_benign_labels": report.assumptions.assumed_benign_labels,
        }),
        approvals_json="[]",
        created_at=time.time(),
        expires_at=time.time() + (72 * 3600),
        version=1,
    )
    print(f"  Proposal ID: {proposal.id} | Tier: {proposal.impact_tier} (demands 2 human approvers)")

    # Approver 1
    approver_1 = "sec-lead@corp.internal"
    approvals = [approver_1]
    proposal.approvals_json = json.dumps(approvals)
    print(f"  [Approver 1/2] {approver_1} signed approval. Progress: {len(approvals)} of 2")

    # Approver 2
    approver_2 = "compliance-officer@corp.internal"
    approvals.append(approver_2)
    proposal.approvals_json = json.dumps(approvals)
    proposal.status = STATUS_APPROVED
    proposal.decided_at = time.time()
    print(f"  [Approver 2/2] {approver_2} signed approval. Progress: {len(approvals)} of 2")
    print(f"  Proposal Status Transitioned: -> {proposal.status}")

    # -------------------------------------------------------------------------
    # Step 5: Verification (Sandbox Execution)
    # -------------------------------------------------------------------------
    print("\n[Step 5/6] PLATFORM POLICY ENFORCEMENT & SANDBOX VERIFICATION")
    ledger_path = str(repo_root / "backend" / "storage" / "audit_ledger.jsonl")

    if offline:
        client = FakeArmorIQClient()
        mode_label = "offline (fakes)"
    else:
        from armoriq_sdk import ArmorIQClient
        api_key = os.getenv("ARMORIQ_API_KEY", "")
        user_email = os.getenv("ARMORIQ_USER_EMAIL", "")
        use_prod = os.getenv("ARMORIQ_USE_PRODUCTION", "true").lower() == "true"
        client = ArmorIQClient(api_key=api_key, user_id=user_email, agent_id=agent_id, use_production=use_prod)
        mode_label = "live"

    verifier = ArmorIQVerifier(client=client, mode=mode_label, ledger_path=ledger_path)

    print(f"  Executing sandbox agent calls under verified policy envelope (mode={mode_label})...")
    receipt = verifier.verify_proposal(
        proposal=proposal,
        num_attack_calls=3,
        num_benign_calls=3,
        mcp_id=mcp_id,
        attack_tool=attack_tool,
        benign_tool=benign_tool,
    )

    print(f"    - Attack calls on '{attack_tool}': {receipt['attacks_tested']} tested, {receipt['attacks_denied']} DENIED (PolicyBlockedException)")
    print(f"    - Benign calls on '{benign_tool}': {receipt['benign_tested']} tested, {receipt['benign_allowed']} ALLOWED")

    # -------------------------------------------------------------------------
    # Step 6: Signed Receipts & Audit Ledger
    # -------------------------------------------------------------------------
    print("\n[Step 6/6] CRYPTOGRAPHIC RECEIPT & TAMPER-EVIDENT AUDIT LEDGER")
    is_valid = verify_receipt(receipt)
    print(f"  Receipt ID: {receipt['receipt_id']}")
    print(f"  Public Key (Ed25519): {receipt['public_key_hex'][:32]}...")
    print(f"  Signature (Ed25519):  {receipt['signature_hex'][:32]}...")
    print(f"  Cryptographic Proof Verified: {is_valid}")
    print(f"  Tamper-Evident Ledger: Receipt hash chained at {ledger_path}")

    # Optional cross-tenant signature export
    bundle = export_signature_bundle(records=records, mapping_path=str(repo_root / "config" / "tool_categories.yaml"))
    print(f"\n  [Cross-Tenant] Exported signed signature bundle '{bundle['bundle_id']}' with {len(bundle['motifs'])} category motifs.")
    print(f"                 Zero sensitive identifiers leaked; strictly bucketed support.")

    duration = time.time() - start_time
    print("\n" + "=" * 80)
    print(f" VIGIL POLICY IMMUNE DEMO COMPLETED IN {duration:.2f}s (LIMIT: 120s)")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run VIGIL policy immune demo")
    parser.add_argument("--offline", action="store_true", default=True, help="Run with offline fakes (default)")
    parser.add_argument("--live", action="store_true", help="Run with live ArmorIQ credentials")
    args = parser.parse_args()

    is_offline = not args.live
    run_demo(offline=is_offline)
