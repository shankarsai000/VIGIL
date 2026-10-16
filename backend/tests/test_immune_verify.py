"""Tests for VIGIL Phase M5: ArmorIQ Verification and Signed Receipts."""

import copy
import json
import os
import tempfile
import pytest

from armoriq_sdk.exceptions import (
    IntentMismatchException,
    PolicyBlockedException,
)
from backend.app.immune.verify import (
    ArmorIQVerifier,
    FakeArmorIQClient,
    VerificationFailure,
    canonical_json_bytes,
    get_or_create_ed25519_key,
    sign_receipt,
    verify_receipt,
)
from backend.app.immune.workflow import (
    STATUS_APPROVED,
    STATUS_PROPOSED,
    STATUS_REJECTED,
    PolicyProposalRecord,
)
from backend.app.runtime.ledger import AuditLedger


@pytest.fixture
def temp_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_file = os.path.join(tmpdir, "audit_ledger.jsonl")
        key_file = os.path.join(tmpdir, "receipt_ed25519.key")
        yield {"ledger_path": ledger_file, "key_path": key_file}


@pytest.fixture
def approved_proposal():
    return PolicyProposalRecord(
        id="prop-test-001",
        status=STATUS_APPROVED,
        agent_id="customer-bot",
        mcp_id="vigil-tools",
        tool="billing_database",
        impact_tier="HIGH",
        replay_json=json.dumps({"coverage": 1.0, "status": "ACCEPT"}),
        assumptions_json=json.dumps({"unlabelled_traffic": "assumed benign"}),
        approvals_json=json.dumps(["secops.officer1@corp.internal", "secops.officer2@corp.internal"]),
        created_at=1000.0,
        expires_at=1000.0 + 72 * 3600,
        decided_at=2000.0,
        version=1,
    )


def test_offline_verification_passes(temp_env, approved_proposal):
    """Offline mode runs verification with fake SDK raising real PolicyBlockedException."""
    fake_client = FakeArmorIQClient()
    verifier = ArmorIQVerifier(
        client=fake_client,
        mode="offline (fakes)",
        ledger_path=temp_env["ledger_path"],
        receipt_key_path=temp_env["key_path"],
    )

    receipt = verifier.verify_proposal(
        approved_proposal,
        num_attack_calls=3,
        num_benign_calls=3,
        attack_tool="billing_database",
        benign_tool="order_status",
    )

    assert receipt["verified"] is True
    assert receipt["mode"] == "offline (fakes)"
    assert receipt["attacks_tested"] == 3
    assert receipt["attacks_denied"] == 3
    assert receipt["benign_tested"] == 3
    assert receipt["benign_allowed"] == 3

    # All attack calls were denied with PolicyBlockedException
    for call in receipt["attack_calls"]:
        assert call["outcome"] == "DENIED"
        assert call["exception_class"] == "PolicyBlockedException"
        assert call["enforcement_action"] == "block"
        assert call["layer"] == "opa"

    # All benign calls succeeded
    for call in receipt["benign_calls"]:
        assert call["outcome"] == "ALLOWED"

    # Receipt is signed and verified
    assert "signature_hex" in receipt
    assert "public_key_hex" in receipt
    assert verify_receipt(receipt) is True

    # Audit ledger entry was recorded
    ledger = AuditLedger(temp_env["ledger_path"])
    verify_res = ledger.verify()
    assert verify_res.ok is True
    assert verify_res.entries == 1


def test_intent_mismatch_counts_as_failure(temp_env, approved_proposal):
    """CRITICAL: IntentMismatchException means platform policy never ran, so check FAILS."""
    fake_client = FakeArmorIQClient(simulate_plan_mismatch=True)
    verifier = ArmorIQVerifier(
        client=fake_client,
        mode="offline (fakes)",
        ledger_path=temp_env["ledger_path"],
        receipt_key_path=temp_env["key_path"],
    )

    with pytest.raises(VerificationFailure) as exc_info:
        verifier.verify_proposal(
            approved_proposal,
            num_attack_calls=2,
            num_benign_calls=2,
            attack_tool="billing_database",
            benign_tool="order_status",
        )

    err_msg = str(exc_info.value)
    assert "IntentMismatchException" in err_msg
    assert "platform policy never ran" in err_msg


def test_unapproved_proposal_cannot_be_verified(temp_env):
    """Proposal with status PROPOSED or REJECTED cannot be verified."""
    unapproved = PolicyProposalRecord(
        id="prop-unapproved",
        status=STATUS_PROPOSED,
        agent_id="customer-bot",
        mcp_id="vigil-tools",
        tool="billing_database",
        impact_tier="LOW",
        replay_json="{}",
        assumptions_json="{}",
        approvals_json="[]",
        created_at=1000.0,
        expires_at=200000.0,
        version=1,
    )

    verifier = ArmorIQVerifier(
        client=FakeArmorIQClient(),
        ledger_path=temp_env["ledger_path"],
        receipt_key_path=temp_env["key_path"],
    )

    with pytest.raises(VerificationFailure) as exc_info:
        verifier.verify_proposal(unapproved)
    assert "Only APPROVED proposals can be verified" in str(exc_info.value)


def test_receipt_cryptographic_verification_and_tamper_detection(temp_env, approved_proposal):
    """Receipt verifies with public key; any modification causes verification to fail."""
    verifier = ArmorIQVerifier(
        client=FakeArmorIQClient(),
        ledger_path=temp_env["ledger_path"],
        receipt_key_path=temp_env["key_path"],
    )

    receipt = verifier.verify_proposal(approved_proposal, num_attack_calls=2, num_benign_calls=2)

    # 1. Unmodified receipt verifies
    assert verify_receipt(receipt) is True

    # 2. Tampered attacks count fails
    tampered_1 = copy.deepcopy(receipt)
    tampered_1["attacks_denied"] = 0
    assert verify_receipt(tampered_1) is False

    # 3. Tampered proposal_id fails
    tampered_2 = copy.deepcopy(receipt)
    tampered_2["proposal_id"] = "prop-tampered-999"
    assert verify_receipt(tampered_2) is False

    # 4. Tampered signature fails
    tampered_3 = copy.deepcopy(receipt)
    tampered_3["signature_hex"] = "a" * len(tampered_3["signature_hex"])
    assert verify_receipt(tampered_3) is False

    # 5. Tampered public key fails
    tampered_4 = copy.deepcopy(receipt)
    tampered_4["public_key_hex"] = "0" * len(tampered_4["public_key_hex"])
    assert verify_receipt(tampered_4) is False


def test_private_key_lives_outside_repo(temp_env):
    """Private key lives at RECEIPT_KEY_PATH outside repo."""
    key = get_or_create_ed25519_key(temp_env["key_path"])
    assert os.path.exists(temp_env["key_path"])

    # Reloading returns the exact same key
    key_reloaded = get_or_create_ed25519_key(temp_env["key_path"])
    sig = key.sign(b"test-bytes")
    key_reloaded.public_key().verify(sig, b"test-bytes")
