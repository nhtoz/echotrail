"""Heuristic injection scanner with severity-weighted scoring.

MVP-grade: regex heuristics that flag content commonly seen in prompt
injection. Flags are advisory highlights; each rule carries a severity
and weight so events and sessions get a cumulative risk score. The
recorder's core value remains the evidence trail, not detection.
"""

from __future__ import annotations

import re

SEVERITY_WEIGHTS = {"high": 8, "medium": 5, "low": 2}

# (pattern, verdict label, severity)
PATTERNS: list[tuple[str, str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction override", "high"),
    (r"disregard\s+(your|the)\s+(system\s+prompt|instructions|rules)", "instruction override", "high"),
    (r"you\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|god)\s*mode", "persona hijack", "medium"),
    (r"do\s+not\s+(tell|inform|alert)\s+(the\s+)?(user|human|operator)", "concealment request", "high"),
    (r"(exfiltrate|forward|send)\s+.{0,40}(credentials|password|api\s*key|secret|token)", "credential exfiltration", "high"),
    (r"curl\s+.{0,60}\|\s*(ba)?sh", "remote code execution", "high"),
    (r"base64\s+-d", "encoded payload", "low"),
    (r"<\s*(system|assistant)\s*>", "role tag smuggling", "medium"),
    (r"IMPORTANT:\s+new\s+instructions", "instruction override", "high"),
    (r"instead\s+of\s+.{0,60},?\s*(send|email|post|upload)\s+it\s+to", "redirection", "medium"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label, sev) for p, label, sev in PATTERNS]


def scan_text(text: str) -> list[dict[str, object]]:
    """Return findings {label, match, severity, weight, pattern} for a blob of text."""
    findings = []
    for rx, label, sev in _COMPILED:
        m = rx.search(text)
        if m:
            findings.append({
                "label": label,
                "match": m.group(0)[:200],
                "severity": sev,
                "weight": SEVERITY_WEIGHTS[sev],
                "pattern": rx.pattern,
            })
    return findings


def scan_payload(payload: object) -> list[dict[str, object]]:
    """Recursively scan any JSON-serializable payload."""
    findings: list[dict[str, object]] = []
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


def risk_score(findings: list[dict[str, object]]) -> int:
    """Cumulative severity-weighted risk score for a set of findings."""
    return sum(int(f.get("weight", 0)) for f in findings)
