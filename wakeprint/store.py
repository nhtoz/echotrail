"""Tamper-evident trace store.

Each session is an append-only JSONL file. Every event embeds the SHA-256
hash of the previous event line, forming a hash chain. Any edit, deletion,
or reordering of past events breaks verification from that point forward.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .canonical import canonical as _canonical, canonical_legacy as _canonical_legacy

GENESIS = "0" * 64
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")

# One lock per session file, shared by every TraceStore in the process, so
# concurrent writers (e.g. the MCP proxy's two relay threads) can't both
# read the same chain head and fork the chain.
_file_locks: dict[str, threading.Lock] = {}
_file_locks_guard = threading.Lock()


def _lock_for(path: Path) -> threading.Lock:
    key = os.path.normcase(os.path.abspath(path))
    with _file_locks_guard:
        return _file_locks.setdefault(key, threading.Lock())


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
        with _lock_for(path):
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
                    "risk": sum(
                        e.get("payload", {}).get("_risk", 0) for e in events[1:]
                        if isinstance(e.get("payload"), dict)
                    ),
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
            if not self.hash_matches(body, claimed):
                return VerificationResult(False, count, event.get("seq"), "event content altered (hash mismatch)")
            prev_hash = claimed
            count += 1
        return VerificationResult(True, count)

    # -- internals -------------------------------------------------------

    def _path(self, session_id: str) -> Path:
        # session ids reach here from URLs and CLI args; anything that could
        # name a file outside the store (separators, "..") cannot exist in it
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id) or ".." in session_id:
            raise FileNotFoundError(f"invalid session id: {session_id!r}")
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

    @staticmethod
    def hash_matches(body: dict[str, Any], claimed: str | None) -> bool:
        """True if `claimed` is the event hash under the current canonical
        form, or under the pre-v0.13 form that older traces were written with."""
        if hashlib.sha256(_canonical(body)).hexdigest() == claimed:
            return True
        return hashlib.sha256(_canonical_legacy(body)).hexdigest() == claimed
