"""Hash-chained audit ledger.

Each entry stores the hash of the entry before it. Editing, deleting, or reordering any entry breaks the chain
from that point onward, and verify() finds the first broken entry.

This is tamper-evident, not tamper-proof. Whoever controls the file can rewrite the whole chain. For stronger
guarantees, periodically anchor the latest hash somewhere outside this machine (for example an ArmorIQ trace).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

GENESIS_HASH = "0" * 64
_BODY_KEYS = ("seq", "ts", "prev_hash", "record")


def _digest(body: Dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    last_hash: str
    bad_seq: Optional[int] = None
    reason: str = ""


class AuditLedger:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._load_tail()

    def _load_tail(self) -> Tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS_HASH
        seq, last = 0, GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    row = json.loads(line)
                    seq, last = row["seq"], row["hash"]
        return seq, last

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            body = {
                "seq": self._seq + 1,
                "ts": round(time.time(), 3),
                "prev_hash": self._last_hash,
                "record": record,
            }
            entry = {**body, "hash": _digest(body)}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._seq, self._last_hash = entry["seq"], entry["hash"]
            return entry

    def verify(self) -> VerifyResult:
        if not self.path.exists():
            return VerifyResult(ok=True, entries=0, last_hash=GENESIS_HASH)
        expected_seq, prev, count = 1, GENESIS_HASH, 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("seq") != expected_seq:
                    return VerifyResult(False, count, prev, row.get("seq"), "sequence gap, duplicate, or reorder")
                if row.get("prev_hash") != prev:
                    return VerifyResult(False, count, prev, row.get("seq"), "previous-hash link is broken")
                body = {key: row.get(key) for key in _BODY_KEYS}
                if _digest(body) != row.get("hash"):
                    return VerifyResult(False, count, prev, row.get("seq"), "entry content does not match its hash")
                prev, expected_seq, count = row["hash"], expected_seq + 1, count + 1
        return VerifyResult(ok=True, entries=count, last_hash=prev)
