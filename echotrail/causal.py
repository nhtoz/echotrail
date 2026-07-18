"""Causal tracing: link injection origins to the downstream actions they caused.

For every flagged event ("origin"), later action events are linked in two ways:

- taint link (strong): a suspicious token — email, URL, IP, host — that first
  appeared in the origin's content shows up in a later tool call or model
  response. E.g. the poisoned ticket says "send it to attacker@evil.example"
  and a later send_email call targets exactly that address.
- temporal link (weak): the action simply happened after the origin. Listed
  so an investigator sees the full blast-radius window, clearly separated
  from evidence-backed links.

This is deliberately evidence-based string analysis, not model inference:
every link cites the exact token and where it appeared. An investigator can
check each claim by hand — which is the standard evidence must meet.
"""

from __future__ import annotations

import json
import re
from typing import Any

ACTION_TYPES = {"tool_call", "tool_result", "llm_response", "tool_error"}

# tokens worth tracking from injected content into later actions
_TAINT_PATTERNS = [
    re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),          # emails
    re.compile(r"https?://[^\s\"'<>]+"),                                     # urls
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                              # IPs
    re.compile(r"\b[a-zA-Z0-9-]+\.(?:example|evil|attacker)[a-zA-Z0-9.-]*"), # suspicious hosts
]


def _text_of(payload: Any) -> str:
    try:
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return str(payload)


def _taint_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for rx in _TAINT_PATTERNS:
        tokens.update(m.lower() for m in rx.findall(text))
    return tokens


def causal_analysis(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return incident groups: each flagged origin with its linked downstream actions."""
    flagged = [
        e for e in events
        if isinstance(e.get("payload"), dict) and e["payload"].get("_flags")
    ]
    if not flagged:
        return []

    # tokens visible in the session BEFORE each seq, to distinguish
    # "introduced by the injection" from "already legitimately present"
    incidents = []
    for origin in flagged:
        origin_text = _text_of(origin["payload"])
        origin_tokens = _taint_tokens(origin_text)

        # tokens already present before the origin are not evidence
        pre_text = " ".join(
            _text_of(e.get("payload", {})) for e in events if e["seq"] < origin["seq"]
        )
        new_tokens = origin_tokens - _taint_tokens(pre_text)

        affected = []
        for e in events:
            if e["seq"] <= origin["seq"] or e.get("type") not in ACTION_TYPES:
                continue
            # skip other flagged events; they are origins, not consequences
            text = _text_of(e.get("payload", {}))
            matched = sorted(t for t in new_tokens if t in text.lower())
            if matched:
                affected.append({
                    "seq": e["seq"],
                    "type": e["type"],
                    "tool": e.get("payload", {}).get("tool"),
                    "link": "taint",
                    "evidence": matched,
                })
            else:
                affected.append({
                    "seq": e["seq"],
                    "type": e["type"],
                    "tool": e.get("payload", {}).get("tool"),
                    "link": "temporal",
                    "evidence": [],
                })

        incidents.append({
            "origin_seq": origin["seq"],
            "origin_type": origin["type"],
            "verdicts": [f["label"] for f in origin["payload"]["_flags"]],
            "risk": origin["payload"].get("_risk", 0),
            "taint_tokens": sorted(new_tokens),
            "affected": affected,
            "taint_hits": sum(1 for a in affected if a["link"] == "taint"),
        })
    return incidents


def format_report(session_id: str, incidents: list[dict[str, Any]]) -> str:
    """Plain-text incident report for the CLI."""
    if not incidents:
        return f"{session_id}: no flagged events — no incident to trace."
    lines = [f"INCIDENT TRACE — session {session_id}", ""]
    for inc in incidents:
        lines.append(
            f"origin seq {inc['origin_seq']} ({inc['origin_type']}) — "
            f"verdicts: {', '.join(inc['verdicts'])} — risk {inc['risk']}"
        )
        if inc["taint_tokens"]:
            lines.append(f"  injected tokens: {', '.join(inc['taint_tokens'])}")
        for a in inc["affected"]:
            if a["link"] == "taint":
                tool = f" {a['tool']}" if a["tool"] else ""
                lines.append(
                    f"  -> seq {a['seq']} {a['type']}{tool}  [TAINT: {', '.join(a['evidence'])}]"
                )
        weak = [a for a in inc["affected"] if a["link"] == "temporal"]
        if weak:
            lines.append(f"  ({len(weak)} additional downstream event(s) with temporal link only)")
        lines.append("")
    return "\n".join(lines)
