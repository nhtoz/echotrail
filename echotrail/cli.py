"""echotrail command-line interface.

  echotrail list                     show sessions with integrity + risk
  echotrail verify SESSION_ID        verify hash chain + anchors (exit 1 on tamper, CI friendly)
  echotrail verify --all             verify every session
  echotrail serve                    start the replay UI
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
        status = ("ok      " if s.get("sealed") else "unsealed") if s["verified"] else "TAMPERED"
        risk = f"  risk={s['risk']}" if s.get("risk") else ""
        print(f"{s['session_id']}  {_fmt_ts(s['started'])}  {status}  {s['events']:>4} events{risk}  {s['name']}")
    return 0


def cmd_verify(store: TraceStore, session_id: str | None, verify_all: bool,
               ca_file: str | None = None, strict: bool = False) -> int:
    from .anchor import check_anchors

    ids = [s["session_id"] for s in store.sessions()] if verify_all else [session_id]
    failed = 0
    for sid in ids:
        v = store.verify(sid)
        if v.ok:
            seal = "sealed" if v.sealed else "NOT sealed (no session_end: still running, crashed, or truncated)"
            print(f"{sid}: OK, {v.events} events, chain intact, {seal}")
            if strict and not v.sealed:
                failed += 1
        else:
            failed += 1
            where = f" at seq {v.first_bad_seq}" if v.first_bad_seq is not None else ""
            print(f"{sid}: TAMPER DETECTED{where}: {v.reason}")
        for a in check_anchors(store, sid, ca_file):
            label = f"  anchor @seq {a['anchored_seq']} ({a['method']}, {a['created_at']})"
            if a["ok"] is True:
                print(f"{label}: OK, timestamped {a['gen_time']} by {a['tsa']}")
            elif a["ok"] is None:
                print(f"{label}: unverified, {a['reason']}")
                if strict:
                    failed += 1
            else:
                failed += 1
                print(f"{label}: FAILED, {a['reason']}")
    return 1 if failed else 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="echotrail", description="Flight recorder & forensics for AI agents")
    parser.add_argument("--root", default="./traces", help="trace store directory (default ./traces)")
    # --root is also accepted after the subcommand (e.g. in MCP client configs)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=argparse.SUPPRESS, help="trace store directory")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name: str, **kw: object) -> argparse.ArgumentParser:
        return sub.add_parser(name, parents=[common], **kw)  # type: ignore[arg-type]

    add("list", help="list sessions")

    p_verify = add("verify", help="verify hash-chain integrity and anchors")
    p_verify.add_argument("session_id", nargs="?", help="session to verify")
    p_verify.add_argument("--all", action="store_true", help="verify all sessions")
    p_verify.add_argument("--tsa-ca", default=None, help="CA file trusted for timestamp tokens (default: certifi/system)")
    p_verify.add_argument("--strict", action="store_true",
                          help="also fail on unsealed sessions and anchors that cannot be checked")

    p_serve = add("serve", help="start the replay UI")
    p_serve.add_argument("--port", type=int, default=8377)
    p_serve.add_argument("--host", default="127.0.0.1")

    p_export = add("export", help="export a session as a self-verifying evidence zip")
    p_export.add_argument("session_id")
    p_export.add_argument("-o", "--out", default=".", help="output directory (default .)")

    p_anchor = add("anchor", help="anchor chain head to an external RFC 3161 timestamp authority")
    p_anchor.add_argument("session_id")
    p_anchor.add_argument("--tsa", default=None, help="TSA URL (default DigiCert, http://timestamp.digicert.com)")

    p_incident = add("incident", help="causal trace: injection origin -> downstream actions")
    p_incident.add_argument("session_id")

    p_otel = add("otel", help="export a session as OpenTelemetry spans (needs echotrail[otel])")
    p_otel.add_argument("session_id")
    p_otel.add_argument("--endpoint", default=None, help="OTLP HTTP endpoint (default: console output)")

    p_mcp = add("mcp-proxy", help="record any MCP server's traffic with zero agent code changes")
    p_mcp.add_argument("--name", default=None, help="session name (default: mcp:<command>)")
    p_mcp.add_argument("--anchor", nargs="?", const=True, default=None, metavar="TSA_URL",
                       help="RFC 3161-anchor the sealed session on exit (default TSA: DigiCert)")
    p_mcp.add_argument("command", nargs=argparse.REMAINDER,
                       help="the real MCP server command (prefix with --)")

    args = parser.parse_args()
    store = TraceStore(args.root)
    sid = getattr(args, "session_id", None)
    if sid and args.cmd in ("export", "anchor", "incident", "otel") and not store._path(sid).exists():
        print(f"session not found: {sid} (in {args.root})", file=sys.stderr)
        sys.exit(2)

    if args.cmd == "list":
        sys.exit(cmd_list(store))
    if args.cmd == "verify":
        if not args.all and not args.session_id:
            parser.error("provide SESSION_ID or --all")
        sys.exit(cmd_verify(store, args.session_id, args.all, args.tsa_ca, args.strict))
    if args.cmd == "otel":
        try:
            import opentelemetry.sdk  # noqa: F401
            from .otel import export_session
        except ImportError:
            print("OpenTelemetry SDK not installed — run: pip install 'echotrail[otel]'", file=sys.stderr)
            sys.exit(2)
        n = export_session(store, args.session_id, endpoint=args.endpoint)
        print(f"exported {n} span(s)" + (f" to {args.endpoint}" if args.endpoint else " to console"))
        sys.exit(0)
    if args.cmd == "mcp-proxy":
        from .mcp_proxy import main as mcp_main
        cmd = args.command[1:] if args.command and args.command[0] == "--" else args.command
        sys.exit(mcp_main(args.root, args.name, cmd, args.anchor))
    if args.cmd == "incident":
        from .causal import causal_analysis, format_report
        events = list(store.read(args.session_id))
        incidents = causal_analysis(events)
        print(format_report(args.session_id, incidents))
        sys.exit(0)
    if args.cmd == "anchor":
        from .anchor import DEFAULT_TSA, AnchorError, create_anchor
        try:
            rec = create_anchor(store, args.session_id, tsa_url=args.tsa or DEFAULT_TSA)
        except AnchorError as e:
            print(f"anchor failed: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"anchored seq {rec['anchored_seq']} hash {rec['anchored_hash'][:16]}… via {rec['method']}")
        if rec["method"] == "local":
            print("note: install 'echotrail[anchor]' for RFC 3161 external timestamping;")
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
