"""SIEM export — sessions as Elastic Common Schema (ECS) or OCSF records.

One NDJSON line per trace event, ready for Elastic/Logstash, Splunk,
Sentinel, Security Lake or any OCSF-aware pipeline:

    echotrail siem SESSION_ID                    # ECS 8.11 to stdout
    echotrail siem SESSION_ID --format ocsf -o session.ocsf.ndjson

Every record carries the event's seq, hash and prev_hash plus the
session's chain-verification result, so a SIEM alert can always be traced
back to the evidence of record. Like the OTel export, this is a *view*;
the hash-chained trace remains the evidence.

OCSF mapping (schema 1.1.0): every event becomes an API Activity
(class 6003); events flagged by the injection scanner additionally emit a
Detection Finding (class 2004).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterator

from . import __version__
from .causal import causal_analysis
from .store import TraceStore

ECS_VERSION = "8.11.0"
OCSF_VERSION = "1.1.0"

_SEV_RANK = {"low": 1, "medium": 2, "high": 3}
_ECS_SEVERITY = {0: 0, 1: 21, 2: 47, 3: 73}       # Elastic's low/medium/high bands
_OCSF_SEVERITY = {0: 1, 1: 2, 2: 3, 3: 4}         # Informational/Low/Medium/High


def _context(store: TraceStore, session_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events = list(store.read(session_id))
    if not events:
        raise ValueError(f"session {session_id} is empty or missing")
    taint: dict[int, list[int]] = {}
    for inc in causal_analysis(events):
        for a in inc["affected"]:
            if a["link"] == "taint":
                taint.setdefault(a["seq"], []).append(inc["origin_seq"])
    ctx = {
        "session_id": session_id,
        "session_name": events[0].get("name", ""),
        "chain_verified": store.verify(session_id).ok,
        "taint": taint,
    }
    return events, ctx


def _payload(e: dict[str, Any]) -> dict[str, Any]:
    p = e.get("payload")
    return p if isinstance(p, dict) else {}


def _severity_rank(e: dict[str, Any]) -> int:
    flags = _payload(e).get("_flags") or []
    return max((_SEV_RANK.get(f.get("severity"), 0) for f in flags), default=0)


def _echotrail_fields(e: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    p = _payload(e)
    flags = p.get("_flags") or []
    out: dict[str, Any] = {
        "session_id": ctx["session_id"],
        "session_name": ctx["session_name"],
        "seq": e["seq"],
        "type": e["type"],
        "hash": e["hash"],
        "prev_hash": e["prev_hash"],
        "chain_verified": ctx["chain_verified"],
        "payload": json.dumps({k: v for k, v in p.items() if not k.startswith("_")}, ensure_ascii=False),
    }
    for key in ("tool", "provider", "method"):
        if p.get(key):
            out[key] = p[key]
    if flags:
        out["verdicts"] = sorted({f["label"] for f in flags})
        out["matches"] = [f["match"] for f in flags]
        out["risk"] = p.get("_risk", 0)
    if e["seq"] in ctx["taint"]:
        out["taint_origin_seqs"] = ctx["taint"][e["seq"]]
    return out


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _summary(e: dict[str, Any]) -> str:
    p = _payload(e)
    what = p.get("tool") or p.get("provider") or p.get("method") or ""
    return f"echotrail {e['type']}" + (f" {what}" if what else "") + f" (seq {e['seq']})"


# -- ECS ---------------------------------------------------------------------

def _ecs_category(e: dict[str, Any]) -> tuple[list[str], list[str]]:
    t = e["type"]
    if t in ("session_start", "session_end"):
        cat, typ = ["session"], ["start" if t == "session_start" else "end"]
    elif t == "config_snapshot":
        cat, typ = ["configuration"], ["info"]
    else:
        cat, typ = ["api"], ["error" if t.endswith("_error") else "info"]
    if _payload(e).get("_flags"):
        cat, typ = cat + ["intrusion_detection"], typ + ["indicator"]
    return cat, typ


def to_ecs(e: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    flagged = bool(_payload(e).get("_flags"))
    cat, typ = _ecs_category(e)
    et = _echotrail_fields(e, ctx)
    rec: dict[str, Any] = {
        "@timestamp": _iso(e["ts"]),
        "ecs": {"version": ECS_VERSION},
        "message": _summary(e),
        "event": {
            "kind": "alert" if flagged else "event",
            "category": cat,
            "type": typ,
            "action": e["type"],
            "dataset": "echotrail.trace",
            "module": "echotrail",
            "provider": "echotrail",
            "id": f"{ctx['session_id']}:{e['seq']}",
            "sequence": e["seq"],
            "hash": e["hash"],
            "severity": _ECS_SEVERITY[_severity_rank(e)],
            "outcome": "failure" if e["type"].endswith("_error") else "unknown",
        },
        "observer": {"product": "echotrail", "vendor": "echotrail", "version": __version__, "type": "agent-recorder"},
        "labels": {"echotrail_session_id": ctx["session_id"]},
        "tags": ["echotrail", "ai-agent"] + (["prompt-injection"] if flagged else []),
        "echotrail": et,
    }
    if flagged:
        rec["event"]["risk_score"] = float(et["risk"])
        rec["rule"] = {"name": ", ".join(et["verdicts"]), "ruleset": "echotrail-injection-heuristics"}
    return rec


# -- OCSF --------------------------------------------------------------------

def _ocsf_metadata(e: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": OCSF_VERSION,
        "product": {"name": "echotrail", "vendor_name": "echotrail", "version": __version__},
        "uid": f"{ctx['session_id']}:{e['seq']}",
        "correlation_uid": ctx["session_id"],
        "sequence": e["seq"],
        "log_name": "echotrail.trace",
    }


def to_ocsf(e: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    p = _payload(e)
    rank = _severity_rank(e)
    failed = e["type"].endswith("_error")
    time_ms = int(e["ts"] * 1000)
    et = _echotrail_fields(e, ctx)
    operation = p.get("tool") or (f"llm.{p['provider']}" if p.get("provider") else None) or p.get("method") or e["type"]

    activity = {
        "class_uid": 6003, "class_name": "API Activity",
        "category_uid": 6, "category_name": "Application Activity",
        "activity_id": 99, "activity_name": e["type"],
        "type_uid": 600399, "type_name": f"API Activity: {e['type']}",
        "time": time_ms,
        "severity_id": _OCSF_SEVERITY[rank],
        "status_id": 2 if failed else 1, "status": "Failure" if failed else "Success",
        "message": _summary(e),
        "metadata": _ocsf_metadata(e, ctx),
        "actor": {"app_name": ctx["session_name"] or "ai-agent"},
        "api": {"operation": operation, "service": {"name": "echotrail"}},
        "src_endpoint": {"name": "ai-agent"},
        "unmapped": {"echotrail": et},
    }
    out = [activity]
    if p.get("_flags"):
        out.append({
            "class_uid": 2004, "class_name": "Detection Finding",
            "category_uid": 2, "category_name": "Findings",
            "activity_id": 1, "activity_name": "Create",
            "type_uid": 200401, "type_name": "Detection Finding: Create",
            "time": time_ms,
            "severity_id": _OCSF_SEVERITY[rank],
            "risk_score": int(et["risk"]),
            "status_id": 1, "status": "New",
            "message": f"possible prompt injection in {e['type']} (seq {e['seq']}): {', '.join(et['verdicts'])}",
            "metadata": _ocsf_metadata(e, ctx),
            "finding_info": {
                "uid": f"{ctx['session_id']}:{e['seq']}:finding",
                "title": ", ".join(et["verdicts"]),
                "types": et["verdicts"],
                "desc": "; ".join(et["matches"]),
                "analytic": {"name": "echotrail injection heuristics", "type_id": 1, "type": "Rule"},
                "related_events": [{"uid": f"{ctx['session_id']}:{e['seq']}"}],
            },
            "unmapped": {"echotrail": et},
        })
    return out


# -- entry points --------------------------------------------------------------

def export_records(store: TraceStore, session_id: str, fmt: str = "ecs") -> Iterator[dict[str, Any]]:
    """Yield ECS or OCSF records for every event in a session."""
    if fmt not in ("ecs", "ocsf"):
        raise ValueError(f"unknown SIEM format {fmt!r} (use 'ecs' or 'ocsf')")
    events, ctx = _context(store, session_id)
    for e in events:
        if fmt == "ecs":
            yield to_ecs(e, ctx)
        else:
            yield from to_ocsf(e, ctx)


def write_ndjson(store: TraceStore, session_id: str, fmt: str = "ecs", out: str | None = None) -> int:
    """Write records as NDJSON to `out` (or stdout). Returns the record count."""
    f = open(out, "w", encoding="utf-8") if out else sys.stdout
    n = 0
    try:
        for rec in export_records(store, session_id, fmt):
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    finally:
        if out:
            f.close()
    return n
