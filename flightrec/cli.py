"""flightrec command-line interface.

  flightrec list                     show sessions with integrity + risk
  flightrec verify SESSION_ID        verify hash chain (exit 1 on tamper — CI friendly)
  flightrec verify --all             verify every session
  flightrec serve                    start the replay UI
"""

from __future__ import annotations

import argparse
import sys
import time

from .store import TraceStore


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def cmd_list(store: TraceStore) -> int:
    sessions = store.sessions()
    if not sessions:
        print("no sessions found")
        return 0
    for s in sessions:
        status = "ok      " if s["verified"] else "TAMPERED"
        risk = f"  risk={s['risk']}" if s.get("risk") else ""
        print(f"{s['session_id']}  {_fmt_ts(s['started'])}  {status}  {s['events']:>4} events{risk}  {s['name']}")
    return 0


def cmd_verify(store: TraceStore, session_id: str | None, verify_all: bool) -> int:
    from .anchor import check_anchors

    ids = [s["session_id"] for s in store.sessions()] if verify_all else [session_id]
    failed = 0
    for sid in ids:
        v = store.verify(sid)
        if v.ok:
            print(f"{sid}: OK — {v.events} events, chain intact")
        else:
            failed += 1
            print(f"{sid}: TAMPER DETECTED at seq {v.first_bad_seq}: {v.reason}")
        for a in check_anchors(store, sid):
            if a["ok"]:
                print(f"  anchor @seq {a['anchored_seq']} ({a['method']}, {a['created_at']}): OK")
            else:
                failed += 1
                print(f"  anchor @seq {a['anchored_seq']} ({a['method']}, {a['created_at']}): MISMATCH — {a['reason']}")
    return 1 if failed else 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="flightrec", description="Flight recorder & forensics for AI agents")
    parser.add_argument("--root", default="./traces", help="trace store directory (default ./traces)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list sessions")

    p_verify = sub.add_parser("verify", help="verify hash-chain integrity")
    p_verify.add_argument("session_id", nargs="?", help="session to verify")
    p_verify.add_argument("--all", action="store_true", help="verify all sessions")

    p_serve = sub.add_parser("serve", help="start the replay UI")
    p_serve.add_argument("--port", type=int, default=8377)
    p_serve.add_argument("--host", default="127.0.0.1")

    p_export = sub.add_parser("export", help="export a session as a self-verifying evidence zip")
    p_export.add_argument("session_id")
    p_export.add_argument("-o", "--out", default=".", help="output directory (default .)")

    p_anchor = sub.add_parser("anchor", help="anchor chain head to an external RFC 3161 timestamp authority")
    p_anchor.add_argument("session_id")
    p_anchor.add_argument("--tsa", default=None, help="TSA URL (default freetsa.org)")

    args = parser.parse_args()
    store = TraceStore(args.root)

    if args.cmd == "list":
        sys.exit(cmd_list(store))
    if args.cmd == "verify":
        if not args.all and not args.session_id:
            parser.error("provide SESSION_ID or --all")
        sys.exit(cmd_verify(store, args.session_id, args.all))
    if args.cmd == "anchor":
        from .anchor import DEFAULT_TSA, create_anchor
        rec = create_anchor(store, args.session_id, tsa_url=args.tsa or DEFAULT_TSA)
        print(f"anchored seq {rec['anchored_seq']} hash {rec['anchored_hash'][:16]}… via {rec['method']}")
        if rec["method"] == "local":
            print("note: install 'flightrec[anchor]' for RFC 3161 external timestamping;")
            print(f"      until then, publish this hash somewhere public: {rec['anchored_hash']}")
        print(f"anchor record: {rec['_path']}")
        sys.exit(0)
    if args.cmd == "export":
        from .export import build_evidence_bundle
        path = build_evidence_bundle(store, args.session_id, args.out)
        print(f"evidence bundle written: {path}")
        print("verify offline with:  unzip, then  python verify.py")
        sys.exit(0)
    if args.cmd == "serve":
        from . import server
        server._store = store
        import uvicorn
        uvicorn.run(server.app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
