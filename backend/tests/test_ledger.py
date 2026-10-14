"""Audit ledger tests (offline)."""
import json

from backend.app.runtime.ledger import GENESIS_HASH, AuditLedger


def _write_three(path):
    ledger = AuditLedger(path)
    for n in range(3):
        ledger.append({"n": n})
    return path.read_text(encoding="utf-8").splitlines()


def test_an_empty_ledger_is_valid_and_starts_at_genesis(tmp_path):
    result = AuditLedger(tmp_path / "none.jsonl").verify()
    assert result.ok and result.entries == 0 and result.last_hash == GENESIS_HASH


def test_the_chain_survives_restarts(tmp_path):
    path = tmp_path / "ledger.jsonl"
    AuditLedger(path).append({"n": 1})
    AuditLedger(path).append({"n": 2})  # reopened: must continue the chain, not restart it
    AuditLedger(path).append({"n": 3})
    result = AuditLedger(path).verify()
    assert result.ok and result.entries == 3


def test_editing_an_entry_is_detected_at_that_entry(tmp_path):
    path = tmp_path / "ledger.jsonl"
    lines = _write_three(path)
    row = json.loads(lines[1])
    row["record"]["n"] = 999
    lines[1] = json.dumps(row, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = AuditLedger(path).verify()
    assert not result.ok and result.bad_seq == 2


def test_deleting_an_entry_is_detected(tmp_path):
    path = tmp_path / "ledger.jsonl"
    lines = _write_three(path)
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = AuditLedger(path).verify()
    assert not result.ok and result.bad_seq == 3


def test_reordering_entries_is_detected(tmp_path):
    path = tmp_path / "ledger.jsonl"
    lines = _write_three(path)
    lines[0], lines[1] = lines[1], lines[0]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not AuditLedger(path).verify().ok
