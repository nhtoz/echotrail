"""Chain-of-custody evidence bundle export.

Produces a self-contained zip that a third party (auditor, regulator,
insurer, opposing counsel) can verify OFFLINE with Python's standard
library plus the `openssl` CLI. No echotrail install, no network:

    <session_id>_evidence.zip
      events.jsonl     the full trace, byte-for-byte
      anchors/*.json   RFC 3161 timestamp anchors for the chain (if any)
      manifest.json    session metadata and file hashes (informational)
      verify.py        standalone verifier
      README.txt       what this is and how to check it

What the verifier can and cannot prove:

* Integrity: the events form an unbroken SHA-256 chain. On its own this only
  shows the file is internally consistent; whoever exported it could have
  regenerated the whole chain (and the manifest) before handing it over.
* Provenance: an RFC 3161 anchor signed by a TSA the *auditor* trusts proves
  the chain up to the anchored event existed, unchanged, at the TSA's time.
  This is what makes the bundle trustworthy without trusting its sender.

verify.py exit codes: 0 = verified and fully anchored; 2 = internally
consistent but NOT (fully) anchored; 1 = verification failed.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import time
import zipfile
from pathlib import Path

from . import __version__
from . import _tsverify
from .anchor import anchors_for
from .store import TraceStore

_VERIFIER_MAIN = r'''

# ---------------------------------------------------------------------------
# bundle verification
# ---------------------------------------------------------------------------
import hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GENESIS = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main(argv):
    ca = None
    if "--ca" in argv:
        ca = argv[argv.index("--ca") + 1]
    raw = (HERE / "events.jsonl").read_bytes()
    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))

    # 1. integrity: the hash chain
    prev, events = GENESIS, []
    for n, line in enumerate(raw.decode("utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            print(f"FAIL: line {n + 1} is not valid JSON")
            return 1
        body = {k: v for k, v in event.items() if k != "hash"}
        if event.get("prev_hash") != prev:
            print(f"FAIL: chain broken at seq {event.get('seq')} (prev_hash mismatch)")
            return 1
        if hashlib.sha256(canonical(body)).hexdigest() != event.get("hash"):
            print(f"FAIL: event content altered at seq {event.get('seq')} (hash mismatch)")
            return 1
        prev = event["hash"]
        events.append(event)
    if not events:
        print("FAIL: no events")
        return 1
    if hashlib.sha256(raw).hexdigest() != manifest.get("events_sha256"):
        print("note: events.jsonl differs from the manifest hash (manifest is informational only)")
    last = events[-1]
    sealed = last.get("type") == "session_end"
    print(f"OK: hash chain intact across {len(events)} events")
    print("OK: session sealed (ends with session_end)" if sealed else
          "WARN: session NOT sealed; it does not end with session_end, so later events may have been cut off")

    # 2. provenance: RFC 3161 anchors
    by_seq = {e["seq"]: e for e in events}
    anchor_dir = HERE / "anchors"
    anchors = sorted(anchor_dir.glob("*.json")) if anchor_dir.exists() else []
    best = -1
    failed = False
    for p in anchors:
        try:
            a = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            print(f"FAIL: anchor {p.name} is unreadable")
            failed = True
            continue
        seq = a.get("anchored_seq")
        ev = by_seq.get(seq)
        if ev is None or ev.get("hash") != a.get("anchored_hash"):
            print(f"FAIL: anchor {p.name}: chain at seq {seq} does not match the anchored hash")
            failed = True
            continue
        if a.get("method") != "rfc3161":
            print(f"info: anchor {p.name} is a local record only (not externally verifiable), ignored")
            continue
        r = verify_timestamp_token(a.get("token_b64") or a.get("tsr_b64") or "", ev["hash"], ca)
        if r["ok"] is True:
            print(f"OK: anchor @seq {seq} timestamped {r['gen_time']} by {r['tsa']}")
            best = max(best, seq)
        elif r["ok"] is None:
            print(f"WARN: anchor @seq {seq} could not be checked: {r['reason']}")
        else:
            print(f"FAIL: anchor @seq {seq}: {r['reason']}")
            failed = True
    if failed:
        print("VERIFICATION FAILED")
        return 1
    if best < 0:
        print("UNANCHORED: the chain is internally consistent, but nothing proves it was not")
        print("            regenerated by whoever exported it. Treat as unverified provenance.")
        return 2
    if best < last["seq"]:
        print(f"PARTIAL: events up to seq {best} are anchored; seq {best + 1}..{last['seq']} are not covered")
        return 2
    print("EVIDENCE VERIFIED (chain intact and anchored by a trusted timestamp authority)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''


def standalone_verifier() -> str:
    header = ('#!/usr/bin/env python3\n"""Standalone echotrail evidence verifier: Python stdlib + openssl CLI.\n\n'
              'Usage:  python verify.py [--ca TRUSTED_CA_FILE]\n'
              'Exit:   0 verified and anchored, 2 consistent but not anchored, 1 failed.\n"""\n')
    src = inspect.getsource(_tsverify)
    return header + src + _VERIFIER_MAIN


README = """ECHOTRAIL EVIDENCE BUNDLE
=========================
Session: {session_id}
Exported: {exported_at} (UTC)
Generated by echotrail v{version}

This bundle contains a tamper-evident record of an AI agent session:
every model request/response and tool call, hash-chained with SHA-256,
plus any RFC 3161 timestamp anchors taken for the chain.

To verify independently (Python 3 and OpenSSL, no installation):

    python verify.py                 # uses your system / certifi CA store
    python verify.py --ca your.pem   # or a CA bundle you choose

Exit code 0: chain intact AND anchored by a timestamp authority you trust.
Exit code 2: chain intact, but not (fully) anchored. The exporter could
             have regenerated it; do not treat it as independent proof.
Exit code 1: verification failed.

The manifest is informational. Trust comes from the hash chain plus the
TSA signatures, checked against YOUR trust store, never one in this zip.
"""


def build_evidence_bundle(store: TraceStore, session_id: str, out_dir: str | Path = ".") -> Path:
    """Export a session as a self-verifying evidence zip. Returns the zip path."""
    events = list(store.read(session_id))
    if not events:
        raise ValueError(f"session {session_id} is empty or missing")
    v = store.verify(session_id)

    raw = ("\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n").encode("utf-8")
    head = events[0]
    flagged = [e for e in events[1:] if isinstance(e.get("payload"), dict) and e["payload"].get("_flags")]
    anchors = [a for a in anchors_for(store, session_id) if a.get("method") != "corrupt"]

    manifest = {
        "bundle_format": 2,
        "echotrail_version": __version__,
        "session_id": session_id,
        "session_name": head.get("name", ""),
        "session_started_ts": head["ts"],
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_count": len(events),
        "events_sha256": hashlib.sha256(raw).hexdigest(),
        "final_chain_hash": events[-1]["hash"],
        "sealed": v.sealed,
        "anchors": [{"seq": a.get("anchored_seq"), "method": a.get("method")} for a in anchors],
        "verification_at_export": {
            "ok": v.ok, "events": v.events,
            "first_bad_seq": v.first_bad_seq, "reason": v.reason,
        },
        "flagged_event_seqs": [e["seq"] for e in flagged],
        "total_risk_score": sum(e["payload"].get("_risk", 0) for e in flagged),
    }

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{session_id}_evidence.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("events.jsonl", raw)
        z.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        for i, a in enumerate(anchors):
            rec = {k: val for k, val in a.items() if not k.startswith("_")}
            z.writestr(f"anchors/anchor_{i:03d}_seq{a.get('anchored_seq')}.json", json.dumps(rec, indent=2))
        z.writestr("verify.py", standalone_verifier())
        z.writestr("README.txt", README.format(
            session_id=session_id, exported_at=manifest["exported_at"], version=__version__))
    return zip_path
