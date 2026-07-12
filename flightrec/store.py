"""Tamper-evident trace store.

Each session is an append-only JSONL file. Every event embeds the SHA-256
hash of the previous event line, forming a hash chain. Any edit, deletion,
or reordering of past events breaks verification from that point forward.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass
class VerificationResult:
    ok: bool
    events: int
    first_bad_seq: int | None = None
    reason: str | None = None


class TraceStore:
    """Append-only, hash-chained session store on the local filesystem."""

    def __init__(self, root: str | Path = "./traces"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # -- writing ---------------------------------------------------------

    def create_session(self, name: str, metadata: dict[str, Any] | None = None) -> str:
        session_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
        path = self._path(session_id)
        header = {
            "seq": 0,
            "type": "session_start",
            "ts": time.time(),
            "session_id": session_id,
            "name": name,
            "metadata": metadata or {},
            "prev_hash": GENESIS,
        }
        header["hash"] = self._hash_event(header)
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(header, ensure_ascii=False) + "\n")
        return session_id

    def append(self, session_id: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        path = self._path(session_id)
        last = self._last_event(path)
        event = {
            "seq": last["seq"] + 1,
            "type": event_type,
            "ts": time.time(),
            "session_id": session_id,
            "payload": payload,
            "prev_hash": last["hash"],
        }
        event["hash"] = self._hash_event(event)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return event

    # -- reading ---------------------------------------------------------

    def sessions(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.root.glob("*.jsonl"), reverse=True):
            try:
                events = list(self.read(p.stem))
            except Exception:
                continue
            if not events:
                continue
            head = events[0]
            out.append(
                {
                    "session_id": head["session_id"],
                    "name": head.get("name", ""),
                    "started": head["ts"],
                    "events": len(events),
                    "verified": self.verify(p.stem).ok,
                }
            )
        return out

    def read(self, session_id: str) -> Iterator[dict[str, Any]]:
        with open(self._path(session_id), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self, session_id: str) -> VerificationResult:
        prev_hash = GENESIS
        count = 0
        for event in self.read(session_id):
            claimed = event.get("hash")
            body = {k: v for k, v in event.items() if k != "hash"}
            if event.get("prev_hash") != prev_hash:
                return VerificationResult(False, count, event.get("seq"), "chain broken (prev_hash mismatch)")
            if self._hash_event(body) != claimed:
                return VerificationResult(False, count, event.get("seq"), "event content altered (hash mismatch)")
            prev_hash = claimed
            count += 1
        return VerificationResult(True, count)

    # -- internals -------------------------------------------------------

    def _path(self, session_id: str) -> Path:
        return self.root / f"{session_id}.jsonl"

    def _last_event(self, path: Path) -> dict[str, Any]:
        last = None
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            raise ValueError(f"empty session file: {path}")
        return json.loads(last)

    @staticmethod
    def _hash_event(body: dict[str, Any]) -> str:
        return hashlib.sha256(_canonical(body)).hexdigest()
