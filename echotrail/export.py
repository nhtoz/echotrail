"""Chain-of-custody evidence bundle export.

Produces a self-contained zip that a third party (auditor, regulator,
insurer, opposing counsel) can verify OFFLINE with nothing but Python's
standard library — no echotrail install, no network, no trust in us:

    <session_id>_evidence.zip
      events.jsonl     the full trace, byte-for-byte
      manifest.json    session metadata, verification result, file sha256
      anchors/*.json   RFC 3161 (or local) anchor records for the session
      verify.py        standalone dependency-free verifier
      README.txt       what this is and how to check it
"""

from __future__ import annotations

import hashlib
import inspect
import json
import time
import zipfile
from pathlib import Path

from . import __version__, canonical as _canonical_mod, tsr as _tsr_mod
from .anchor import anchors_for, check_anchor
from .store import TraceStore

_VERIFIER_HEAD = '''#!/usr/bin/env python3
"""Standalone echotrail evidence verifier — stdlib only, no install needed.

Usage:  python verify.py [--tsa-ca TSA_CA_CERT.pem]

Checks (1) events.jsonl matches the sha256 recorded in manifest.json,
(2) the SHA-256 hash chain across all events is intact,
(3) every anchor in anchors/ matches the chain, and each RFC 3161 token
    timestamps exactly the anchored hash. With --tsa-ca (and openssl on
    PATH) the token's signature is checked against that TSA CA too.
Exit code 0 = evidence verified; 1 = verification FAILED.
"""
'''

_VERIFIER_MAIN = '''

# ---- verifier ---------------------------------------------------------------
import argparse, base64, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GENESIS = "0" * 64


def hash_ok(body, claimed):
    return (hashlib.sha256(canonical(body)).hexdigest() == claimed
            or hashlib.sha256(canonical_legacy(body)).hexdigest() == claimed)


def main():
    ap = argparse.ArgumentParser(description="verify an echotrail evidence bundle")
    ap.add_argument("--tsa-ca", help="CA certificate of the timestamp authority (PEM); "
                                     "obtain it from the TSA yourself, not from this bundle")
    args = ap.parse_args()

    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    raw = (HERE / "events.jsonl").read_bytes()

    file_hash = hashlib.sha256(raw).hexdigest()
    if file_hash != manifest["events_sha256"]:
        print(f"FAIL: events.jsonl sha256 mismatch\\n  expected {manifest['events_sha256']}\\n  actual   {file_hash}")
        return 1
    print(f"OK: events.jsonl sha256 matches manifest ({file_hash[:16]}...)")

    prev, count, events = GENESIS, 0, {}
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        body = {k: v for k, v in event.items() if k != "hash"}
        if event.get("prev_hash") != prev:
            print(f"FAIL: chain broken at seq {event.get('seq')} (prev_hash mismatch)")
            return 1
        if not hash_ok(body, event.get("hash")):
            print(f"FAIL: event content altered at seq {event.get('seq')} (hash mismatch)")
            return 1
        prev = event["hash"]
        events[event["seq"]] = event
        count += 1
    if count != manifest["event_count"] or prev != manifest["final_chain_hash"]:
        print(f"FAIL: chain does not match manifest (manifest {manifest['event_count']} events, file {count})")
        return 1
    print(f"OK: hash chain intact across {count} events")

    head_seq = max(events) if events else None
    listed = manifest.get("anchors", [])
    files = sorted((HERE / "anchors").glob("*.json")) if (HERE / "anchors").is_dir() else []
    if len(files) != len(listed):
        print(f"FAIL: manifest lists {len(listed)} anchor(s), bundle contains {len(files)}")
        return 1
    if not files:
        print("NOTE: no anchor in bundle; a full rewrite of the chain before export would not be detectable")
    for f in files:
        a = json.loads(f.read_text(encoding="utf-8"))
        seq = a["anchored_seq"]
        ev = events.get(seq)
        where = "chain head" if seq == head_seq else f"chain at seq {seq}"
        if ev is None or ev.get("hash") != a["anchored_hash"]:
            print(f"FAIL: anchor {f.name} does not match the chain at seq {seq}")
            return 1
        if a["method"] != "rfc3161":
            print(f"NOTE: local anchor (not externally timestamped) matches {where}")
            continue
        try:
            der = base64.b64decode(a.get("tsr_b64", ""), validate=True)
        except ValueError:
            der = b""
        ok, detail = check_token(der, a["anchored_hash"])
        if not ok:
            print(f"FAIL: RFC 3161 anchor {f.name}: {detail}")
            return 1
        print(f"OK: RFC 3161 anchor matches {where} ({detail})")
        if args.tsa_ca:
            sig_ok, sig_detail = verify_signature(der, a["anchored_hash"], args.tsa_ca)
            if sig_ok is None:
                print(f"FAIL: --tsa-ca given but {sig_detail}")
                return 1
            if not sig_ok:
                print(f"FAIL: {sig_detail}")
                return 1
            print(f"OK: {sig_detail}")
        else:
            print("NOTE: TSA signature not checked; re-run with --tsa-ca <TSA CA cert> (needs openssl)")

    print("EVIDENCE VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

# The verifier embeds the exact canonical-JSON and token-parsing code the
# library uses, so the two can never drift apart.
STANDALONE_VERIFIER = (
    _VERIFIER_HEAD
    + "\n# ---- echotrail/canonical.py -----------------------------------------------\n"
    + inspect.getsource(_canonical_mod)
    + "\n# ---- echotrail/tsr.py -----------------------------------------------------\n"
    + inspect.getsource(_tsr_mod)
    + _VERIFIER_MAIN
)

README = """ECHOTRAIL EVIDENCE BUNDLE
=========================
Session: {session_id}
Exported: {exported_at} (UTC)
Generated by echotrail v{version}

This bundle contains a tamper-evident record of an AI agent session:
every model request/response and tool call, hash-chained with SHA-256.

To verify independently (requires only Python 3, no installation):

    python verify.py

The verifier checks that events.jsonl matches the sha256 in
manifest.json, that the hash chain is unbroken, and that every anchor in
anchors/ matches the chain. Any modification, deletion, or reordering of
events after export will cause verification to FAIL.

RFC 3161 anchors prove the chain head existed at the time the timestamp
authority (TSA) signed it. To also check that signature, get the TSA's CA
certificate from the TSA itself (not from this bundle) and run:

    python verify.py --tsa-ca tsa_ca.pem      (needs openssl on PATH)
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

    by_seq = {e["seq"]: e for e in events}
    anchors = []
    for i, a in enumerate(anchors_for(store, session_id)):
        a = {k: val for k, val in a.items() if not k.startswith("_")}
        anchors.append((f"anchors/{i:03d}_seq{a['anchored_seq']}.json", a))

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
        "verification_at_export": {
            "ok": v.ok, "events": v.events,
            "first_bad_seq": v.first_bad_seq, "reason": v.reason,
        },
        "anchors": [
            {"file": name, "anchored_seq": a["anchored_seq"], "method": a["method"],
             "ok_at_export": check_anchor(a, by_seq)["ok"]}
            for name, a in anchors
        ],
        "flagged_event_seqs": [e["seq"] for e in flagged],
        "total_risk_score": sum(e["payload"].get("_risk", 0) for e in flagged),
    }

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{session_id}_evidence.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("events.jsonl", raw)
        z.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        for name, a in anchors:
            z.writestr(name, json.dumps(a, indent=2))
        z.writestr("verify.py", STANDALONE_VERIFIER)
        z.writestr("README.txt", README.format(
            session_id=session_id, exported_at=manifest["exported_at"], version=__version__))
    return zip_path
