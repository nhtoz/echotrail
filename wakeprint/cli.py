"""wakeprint command-line interface.

  wakeprint list                     show sessions with integrity + risk
  wakeprint verify SESSION_ID        verify hash chain (exit 1 on tamper — CI friendly)
  wakeprint verify --all             verify every session
  wakeprint serve                    start the replay UI
  wakeprint siem SESSION_ID          export ECS (default) or OCSF NDJSON for a SIEM
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


def cmd_verify(store: TraceStore, session_id: str | None, verify_all: bool, tsa_ca: str | None = None) -> int:
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
        for a in check_anchors(store, sid, tsa_ca=tsa_ca):
            if a["ok"]:
                extra = f", {a['tsa_time']}, signature {a['signature']}" if a["method"] == "rfc3161" else ""
                print(f"  anchor @seq {a['anchored_seq']} ({a['method']}, {a['created_at']}{extra}): OK")
            else:
                failed += 1
                print(f"  anchor @seq {a['anchored_seq']} ({a['method']}, {a['created_at']}): MISMATCH — {a['reason']}")
    return 1 if failed else 0


def main() -> None:
    # piped output on Windows defaults to the ANSI code page, which can't
    # encode session names or payload text in most scripts
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(prog="wakeprint", description="Flight recorder & forensics for AI agents")
    parser.add_argument("--root", default="./traces", help="trace store directory (default ./traces)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list sessions")

    p_verify = sub.add_parser("verify", help="verify hash-chain integrity")
    p_verify.add_argument("session_id", nargs="?", help="session to verify")
    p_verify.add_argument("--all", action="store_true", help="verify all sessions")
    p_verify.add_argument("--tsa-ca", default=None,
                          help="TSA CA certificate (PEM) to check RFC 3161 token signatures (needs openssl)")

    p_serve = sub.add_parser("serve", help="start the replay UI")
    p_serve.add_argument("--port", type=int, default=8377)
    p_serve.add_argument("--host", default="127.0.0.1")

    p_export = sub.add_parser("export", help="export a session as a self-verifying evidence zip")
    p_export.add_argument("session_id")
    p_export.add_argument("-o", "--out", default=".", help="output directory (default .)")

    p_anchor = sub.add_parser("anchor", help="anchor chain head to an external RFC 3161 timestamp authority")
    p_anchor.add_argument("session_id")
    p_anchor.add_argument("--tsa", default=None, help="TSA URL (default freetsa.org)")

    p_incident = sub.add_parser("incident", help="causal trace: injection origin -> downstream actions")
    p_incident.add_argument("session_id")

    p_otel = sub.add_parser("otel", help="export a session as OpenTelemetry spans (needs wakeprint[otel])")
    p_otel.add_argument("session_id")
    p_otel.add_argument("--endpoint", default=None, help="OTLP HTTP endpoint (default: console output)")

    p_siem = sub.add_parser("siem", help="export a session as ECS or OCSF NDJSON for a SIEM")
    p_siem.add_argument("session_id")
    p_siem.add_argument("--format", choices=["ecs", "ocsf"], default="ecs")
    p_siem.add_argument("-o", "--out", default=None, help="output file (default: stdout)")

    p_mcp = sub.add_parser("mcp-proxy", help="record any MCP server's traffic with zero agent code changes")
    p_mcp.add_argument("--name", default=None, help="session name (default: mcp:<command>)")
    p_mcp.add_argument("command", nargs=argparse.REMAINDER,
                       help="the real MCP server command (prefix with --)")

    args = parser.parse_args()
    store = TraceStore(args.root)

    if args.cmd == "list":
        sys.exit(cmd_list(store))
    if args.cmd == "verify":
        if not args.all and not args.session_id:
            parser.error("provide SESSION_ID or --all")
        sys.exit(cmd_verify(store, args.session_id, args.all, args.tsa_ca))
    if args.cmd == "siem":
        from .siem import write_ndjson
        n = write_ndjson(store, args.session_id, args.format, args.out)
        if args.out:
            print(f"wrote {n} {args.format.upper()} record(s) to {args.out}")
        sys.exit(0)
    if args.cmd == "otel":
        try:
            from .otel import export_session
        except ImportError:
            print("OpenTelemetry SDK not installed — run: pip install 'wakeprint[otel]'", file=sys.stderr)
            sys.exit(2)
        n = export_session(store, args.session_id, endpoint=args.endpoint)
        print(f"exported {n} span(s)" + (f" to {args.endpoint}" if args.endpoint else " to console"))
        sys.exit(0)
    if args.cmd == "mcp-proxy":
        from .mcp_proxy import main as mcp_main
        cmd = args.command[1:] if args.command and args.command[0] == "--" else args.command
        sys.exit(mcp_main(args.root, args.name, cmd))
    if args.cmd == "incident":
        from .causal import causal_analysis, format_report
        events = list(store.read(args.session_id))
        incidents = causal_analysis(events)
        print(format_report(args.session_id, incidents))
        sys.exit(0)
    if args.cmd == "anchor":
        from .anchor import DEFAULT_TSA, create_anchor
        rec = create_anchor(store, args.session_id, tsa_url=args.tsa or DEFAULT_TSA)
        print(f"anchored seq {rec['anchored_seq']} hash {rec['anchored_hash'][:16]}… via {rec['method']}")
        if rec["method"] == "local":
            print("note: install 'wakeprint[anchor]' for RFC 3161 external timestamping;")
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
