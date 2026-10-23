"""External timestamp anchoring.

Hash-chaining proves a trace wasn't edited *after* writing, but not *when*
it was written: whoever holds the file could regenerate the whole chain.
Anchoring closes that gap. The chain head hash is sent to an external
RFC 3161 Time-Stamp Authority (TSA), which returns a signed token proving
that exact hash existed at that moment.

Verification checks the token itself, not just the local record: the
token's signature must chain to a CA in the verifier's trust store, and its
message imprint must equal SHA-256 of the chain hash at the anchored seq.
Editing the anchor JSON, swapping in another token or rewriting the chain
all fail.

    pip install "echotrail[anchor]"
    echotrail anchor SESSION_ID          # default TSA: DigiCert (public root)

Without rfc3161ng a *local* anchor record is written. It is a reminder to
publish the hash somewhere public, not proof: it is reported as such.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any, Callable

from ._tsverify import verify_timestamp_token
from .store import TraceStore

# DigiCert's TSA certificate chains to a root in standard trust stores, so
# tokens verify out of the box. (freetsa.org uses a private root and will
# not verify unless you add its CA with --tsa-ca.)
DEFAULT_TSA = "http://timestamp.digicert.com"


class AnchorError(RuntimeError):
    pass


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

    `_timestamper` is injectable for testing; it receives the chain hash
    (hex, as bytes) and must return a DER RFC 3161 TimeStampToken.
    Raises AnchorError if the TSA cannot be reached.
    """
    v = store.verify(session_id)
    if not v.ok:
        raise AnchorError(f"refusing to anchor a chain that does not verify: {v.reason}")
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
        except ImportError:
            rfc3161ng = None
        if rfc3161ng is not None:
            rt = rfc3161ng.RemoteTimestamper(tsa_url, hashname="sha256", include_tsa_certificate=True)

            def timestamper(data: bytes) -> bytes:
                try:
                    return rt.timestamp(data=data)
                except Exception as e:  # network, HTTP or TSA errors
                    raise AnchorError(f"could not get a timestamp from {tsa_url}: {e}") from None

    if timestamper is not None:
        token = timestamper(head_hash.encode())
        record["method"] = "rfc3161"
        record["tsa_url"] = tsa_url
        record["token_b64"] = base64.b64encode(bytes(token)).decode()

    path = _anchor_dir(store) / f"{session_id}.{int(time.time() * 1000)}.json"
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
            out.append({"anchored_seq": None, "created_at": "?", "method": "corrupt", "_file": p.name})
    return out


def check_anchor(record: dict[str, Any], events_by_seq: dict[int, dict[str, Any]],
                 ca_file: str | None = None) -> dict[str, Any]:
    """Check one anchor record against the chain.

    ok:       True  - chain matches and (for rfc3161) the TSA token verifies
              False - mismatch or invalid token: history was rewritten
              None  - local anchor, or token could not be checked here
    """
    base = {"anchored_seq": record.get("anchored_seq"), "created_at": record.get("created_at"),
            "method": record.get("method"), "gen_time": None, "tsa": None}
    if record.get("method") == "corrupt":
        return {**base, "ok": False, "reason": f"anchor file {record.get('_file')} is unreadable"}
    ev = events_by_seq.get(record.get("anchored_seq"))
    if ev is None or ev.get("hash") != record.get("anchored_hash"):
        return {**base, "ok": False, "reason": "chain at anchored seq no longer matches anchored hash"}
    if record.get("method") == "rfc3161":
        token = record.get("token_b64") or record.get("tsr_b64")
        if not token:
            return {**base, "ok": False, "reason": "rfc3161 anchor has no token"}
        r = verify_timestamp_token(token, ev["hash"], ca_file)
        return {**base, "ok": r["ok"], "reason": r["reason"], "gen_time": r["gen_time"], "tsa": r["tsa"]}
    return {**base, "ok": None,
            "reason": "local anchor only: proves nothing unless the hash was published elsewhere"}


def check_anchors(store: TraceStore, session_id: str, ca_file: str | None = None) -> list[dict[str, Any]]:
    try:
        events = {e["seq"]: e for e in store.read(session_id)}
    except Exception:
        events = {}
    return [check_anchor(a, events, ca_file) for a in anchors_for(store, session_id)]
