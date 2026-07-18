"""External timestamp anchoring.

Hash-chaining proves a trace wasn't edited *after* writing — but not
*when* it was written. An operator could fabricate an entire chain after
an incident. Anchoring fixes this: we submit the chain head hash to an
external RFC 3161 Time-Stamp Authority (TSA), which returns a signed
token proving the hash existed at that moment. Any events recorded
before the anchor point can no longer be backdated or rewritten wholesale.

RFC 3161 support uses the optional `rfc3161ng` package:

    pip install "flightrec[anchor]"
    flightrec anchor SESSION_ID

Without it, a local anchor record is still written (useful for manual
publication of the hash — e.g. in a tweet, email, or internal ledger).
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any, Callable

from .store import TraceStore

DEFAULT_TSA = "https://freetsa.org/tsr"


def chain_head(store: TraceStore, session_id: str) -> tuple[int, str]:
    """Return (seq, hash) of the last event in the session's chain."""
    last = None
    for event in store.read(session_id):
        last = event
    if last is None:
        raise ValueError(f"session {session_id} is empty or missing")
    return last["seq"], last["hash"]


def _anchor_dir(store: TraceStore) -> Path:
    d = store.root / "anchors"
    d.mkdir(parents=True, exist_ok=True)
    return d


def create_anchor(
    store: TraceStore,
    session_id: str,
    tsa_url: str = DEFAULT_TSA,
    _timestamper: Callable[[bytes], bytes] | None = None,
) -> dict[str, Any]:
    """Anchor the current chain head. Returns the anchor record.

    `_timestamper` is injectable for testing; by default an RFC 3161
    request is sent to `tsa_url` via the optional rfc3161ng package.
    """
    seq, head_hash = chain_head(store, session_id)
    record: dict[str, Any] = {
        "session_id": session_id,
        "anchored_seq": seq,
        "anchored_hash": head_hash,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": "local",
        "tsa_url": None,
    }

    timestamper = _timestamper
    if timestamper is None:
        try:
            import rfc3161ng  # type: ignore

            rt = rfc3161ng.RemoteTimestamper(tsa_url, hashname="sha256")
            timestamper = lambda data: rt.timestamp(data=data)  # noqa: E731
            record["tsa_url"] = tsa_url
        except ImportError:
            timestamper = None

    if timestamper is not None:
        tsr = timestamper(head_hash.encode())
        record["method"] = "rfc3161"
        record["tsa_url"] = record["tsa_url"] or tsa_url
        record["tsr_b64"] = base64.b64encode(bytes(tsr)).decode()

    path = _anchor_dir(store) / f"{session_id}.{int(time.time())}.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    record["_path"] = str(path)
    return record


def anchors_for(store: TraceStore, session_id: str) -> list[dict[str, Any]]:
    d = store.root / "anchors"
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob(f"{session_id}.*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out


def check_anchors(store: TraceStore, session_id: str) -> list[dict[str, Any]]:
    """Check each anchor against the live chain.

    An anchor is OK if the event at `anchored_seq` still carries
    `anchored_hash`. A mismatch means history before the anchor point was
    rewritten after the anchor was created.
    """
    events = {e["seq"]: e for e in store.read(session_id)}
    results = []
    for a in anchors_for(store, session_id):
        ev = events.get(a["anchored_seq"])
        ok = ev is not None and ev.get("hash") == a["anchored_hash"]
        results.append({
            "anchored_seq": a["anchored_seq"],
            "created_at": a["created_at"],
            "method": a["method"],
            "ok": ok,
            "reason": None if ok else "chain at anchored seq no longer matches anchored hash",
        })
    return results
