/** Heuristic injection scanner — same rules, severities, and weights as the Python package. */

export type Severity = "high" | "medium" | "low";

export const SEVERITY_WEIGHTS: Record<Severity, number> = { high: 8, medium: 5, low: 2 };

const PATTERNS: Array<[RegExp, string, Severity]> = [
  [/ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i, "instruction override", "high"],
  [/disregard\s+(your|the)\s+(system\s+prompt|instructions|rules)/i, "instruction override", "high"],
  [/you\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|god)\s*mode/i, "persona hijack", "medium"],
  [/do\s+not\s+(tell|inform|alert)\s+(the\s+)?(user|human|operator)/i, "concealment request", "high"],
  [/(exfiltrate|forward|send)\s+.{0,40}(credentials|password|api\s*key|secret|token)/i, "credential exfiltration", "high"],
  [/curl\s+.{0,60}\|\s*(ba)?sh/i, "remote code execution", "high"],
  [/base64\s+-d/i, "encoded payload", "low"],
  [/<\s*(system|assistant)\s*>/i, "role tag smuggling", "medium"],
  [/IMPORTANT:\s+new\s+instructions/i, "instruction override", "high"],
  [/instead\s+of\s+.{0,60},?\s*(send|email|post|upload)\s+it\s+to/i, "redirection", "medium"],
];

export interface Finding {
  label: string;
  match: string;
  severity: Severity;
  weight: number;
  pattern: string;
}

export function scanText(text: string): Finding[] {
  const findings: Finding[] = [];
  for (const [rx, label, severity] of PATTERNS) {
    const m = rx.exec(text);
    if (m) {
      findings.push({
        label, match: m[0].slice(0, 200), severity,
        weight: SEVERITY_WEIGHTS[severity], pattern: rx.source,
      });
    }
  }
  return findings;
}

export function scanPayload(payload: unknown): Finding[] {
  const findings: Finding[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === "string") findings.push(...scanText(v));
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v !== null && typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(payload);
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.label} ${f.match}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function riskScore(findings: Finding[]): number {
  return findings.reduce((a, f) => a + f.weight, 0);
}
