"""External timestamp anchoring.

Hash-chaining proves a trace wasn't edited *after* writing — but not
*when* it was written. An operator could fabricate an entire chain after
an incident. Anchoring fixes this: we submit the chain head hash to an
external RFC 3161 Time-Stamp Authority (TSA), which returns a signed
token proving the hash existed at that moment. Any events recorded
before the anchor point can no longer be backdated or rewritten wholesale.

RFC 3161 support uses the optional `rfc3161ng` package:

    pip install "wakeprint[anchor]"
    wakeprint anchor SESSION_ID

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
from .tsr import check_token, verify_signature

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

            # embed the TSA cert so `openssl ts -verify` needs only the CA
            rt = rfc3161ng.RemoteTimestamper(tsa_url, hashname="sha256", include_tsa_certificate=True)
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
    store._path(session_id)  # rejects ids that would glob outside the store
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


def check_anchor(a: dict[str, Any], events: dict[int, dict[str, Any]],
                 tsa_ca: str | Path | None = None) -> dict[str, Any]:
    """Check one anchor record against the chain (events keyed by seq).

    1. the event at `anchored_seq` must still carry `anchored_hash`;
    2. for RFC 3161 anchors, the token must timestamp exactly that hash —
       so editing the anchor record to match a rewritten chain is caught;
    3. with `tsa_ca`, the token's signature is checked against the TSA CA
       (via openssl), so a fabricated token is caught too.
    """
    out = {
        "anchored_seq": a["anchored_seq"],
        "created_at": a["created_at"],
        "method": a["method"],
        "ok": False,
        "reason": None,
        "tsa_time": None,
        "signature": "n/a" if a["method"] != "rfc3161" else "not checked",
    }
    ev = events.get(a["anchored_seq"])
    if ev is None or ev.get("hash") != a["anchored_hash"]:
        out["reason"] = "chain at anchored seq no longer matches anchored hash"
        return out
    if a["method"] == "rfc3161":
        try:
            der = base64.b64decode(a.get("tsr_b64", ""), validate=True)
        except ValueError:
            der = b""
        ok, detail = check_token(der, a["anchored_hash"])
        if not ok:
            out["reason"] = f"RFC 3161 token: {detail}"
            return out
        out["tsa_time"] = detail
        if tsa_ca is not None:
            sig_ok, sig_detail = verify_signature(der, a["anchored_hash"], tsa_ca)
            if sig_ok is False:
                out["signature"] = "invalid"
                out["reason"] = sig_detail
                return out
            out["signature"] = "valid" if sig_ok else sig_detail
    out["ok"] = True
    return out


def check_anchors(store: TraceStore, session_id: str,
                  tsa_ca: str | Path | None = None) -> list[dict[str, Any]]:
    """Check each anchor for a session against the live chain (see check_anchor)."""
    events = {e["seq"]: e for e in store.read(session_id)}
    return [check_anchor(a, events, tsa_ca) for a in anchors_for(store, session_id)]
