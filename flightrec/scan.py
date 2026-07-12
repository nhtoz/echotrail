"""Heuristic injection scanner.

MVP-grade: regex heuristics that flag content commonly seen in prompt
injection. This is intentionally simple — the recorder's value is the
evidence trail, not detection. Flags are advisory highlights in the UI.
"""

from __future__ import annotations

import re

PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction override"),
    (r"disregard\s+(your|the)\s+(system\s+prompt|instructions|rules)", "instruction override"),
    (r"you\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|god)\s*mode", "persona hijack"),
    (r"do\s+not\s+(tell|inform|alert)\s+(the\s+)?(user|human|operator)", "concealment request"),
    (r"(exfiltrate|forward|send)\s+.{0,40}(credentials|password|api\s*key|secret|token)", "credential exfiltration"),
    (r"curl\s+.{0,60}\|\s*(ba)?sh", "remote code execution"),
    (r"base64\s+-d", "encoded payload"),
    (r"<\s*(system|assistant)\s*>", "role tag smuggling"),
    (r"IMPORTANT:\s+new\s+instructions", "instruction override"),
    (r"instead\s+of\s+.{0,60},?\s*(send|email|post|upload)\s+it\s+to", "redirection"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label) for p, label in PATTERNS]


def scan_text(text: str) -> list[dict[str, str]]:
    """Return a list of {pattern, label, match} findings for a blob of text."""
    findings = []
    for rx, label in _COMPILED:
        m = rx.search(text)
        if m:
            findings.append({"label": label, "match": m.group(0)[:200], "pattern": rx.pattern})
    return findings


def scan_payload(payload: object) -> list[dict[str, str]]:
    """Recursively scan any JSON-serializable payload."""
    findings: list[dict[str, str]] = []
    if isinstance(payload, str):
        findings.extend(scan_text(payload))
    elif isinstance(payload, dict):
        for v in payload.values():
            findings.extend(scan_payload(v))
    elif isinstance(payload, (list, tuple)):
        for v in payload:
            findings.extend(scan_payload(v))
    # de-duplicate by label+match
    seen = set()
    unique = []
    for f in findings:
        key = (f["label"], f["match"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
