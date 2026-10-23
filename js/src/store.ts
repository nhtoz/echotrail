/**
 * Tamper-evident trace store — trace-format compatible with the Python
 * package: same JSONL schema, same canonical JSON (sorted keys, no
 * whitespace), same SHA-256 hash chain. A trace written from Node can be
 * verified, replayed, exported, and anchored by the Python CLI.
 */
import { createHash, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export const GENESIS = "0".repeat(64);

export interface TraceEvent {
  seq: number;
  type: string;
  ts: number;
  session_id: string;
  payload?: Record<string, unknown>;
  name?: string;
  metadata?: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface VerificationResult {
  ok: boolean;
  events: number;
  firstBadSeq: number | null;
  reason: string | null;
  sealed?: boolean;
}

/**
 * Canonical JSON, byte-identical to Python's
 *   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
 * which is what the Python CLI hashes. Two details JSON.stringify gets wrong:
 *   - floats: Python writes 1e-05 / 1.5e-07 / 1e+16 where JS writes 0.00001 /
 *     1.5e-7 / 10000000000000000, and keeps "5.0" where JS has 5;
 *   - key order: Python sorts by code point, JS sort() by UTF-16 unit.
 */

/** A number whose original JSON source text is known (used when verifying). */
class SourceNumber {
  constructor(readonly src: string) {}
}

/** Python repr() of a float (shortest round-trip digits, Python's layout). */
export function pyFloatRepr(n: number): string {
  if (Number.isNaN(n)) return "NaN";
  if (n === Infinity) return "Infinity";
  if (n === -Infinity) return "-Infinity";
  const neg = n < 0 || Object.is(n, -0);
  const [mant, expStr] = Math.abs(n).toExponential().split("e");
  const digits = mant.replace(".", "");
  const e = parseInt(expStr, 10);
  let body: string;
  if (n === 0) {
    body = "0.0";
  } else if (e >= -4 && e < 16) {
    if (e >= 0) {
      const intPart = digits.slice(0, e + 1).padEnd(e + 1, "0");
      const frac = digits.slice(e + 1) || "0";
      body = `${intPart}.${frac}`;
    } else {
      body = `0.${"0".repeat(-e - 1)}${digits}`;
    }
  } else {
    const m = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    body = `${m}e${e < 0 ? "-" : "+"}${String(Math.abs(e)).padStart(2, "0")}`;
  }
  return (neg ? "-" : "") + body;
}

/** How Python would re-serialise a JSON number token after json.loads. */
function pyNumberFromSource(src: string): string {
  if (/[.eE]/.test(src)) return pyFloatRepr(Number(src));
  return BigInt(src).toString(); // Python ints are arbitrary precision
}

/** Serialise a JS number the way Python will read it back and re-dump it. */
function pyNumber(n: number): string {
  if (!Number.isFinite(n)) return "null"; // JSON.stringify semantics
  if (Number.isInteger(n) && Math.abs(n) < 1e16) return Object.is(n, -0) ? "0" : String(n);
  return pyFloatRepr(n);
}

function cmpCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator](), ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next(), y = ib.next();
    if (x.done || y.done) return x.done === y.done ? 0 : x.done ? -1 : 1;
    const cx = x.value.codePointAt(0)!, cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx - cy;
  }
}

function serialize(v: unknown, sort: boolean): string {
  if (v instanceof SourceNumber) return pyNumberFromSource(v.src);
  if (v === null || v === undefined) return "null";
  if (typeof v === "number") return pyNumber(v);
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "string" || typeof v === "boolean") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map((x) => (x === undefined || typeof x === "function" ? "null" : serialize(x, sort))).join(",")}]`;
  if (typeof v === "object") {
    const anyV = v as { toJSON?: () => unknown };
    if (typeof anyV.toJSON === "function") return serialize(anyV.toJSON(), sort);
    let keys = Object.keys(v as object).filter((k) => {
      const x = (v as Record<string, unknown>)[k];
      return x !== undefined && typeof x !== "function";
    });
    if (sort) keys = keys.sort(cmpCodePoints);
    return `{${keys.map((k) => `${JSON.stringify(k)}:${serialize((v as Record<string, unknown>)[k], sort)}`).join(",")}}`;
  }
  return "null";
}

export function canonical(obj: unknown): string {
  return serialize(obj, true);
}

/** Line format written to disk (unsorted, Python-compatible numbers). */
export function toLine(obj: unknown): string {
  return serialize(obj, false);
}

/** Parse keeping each number's source text, so verification hashes exactly
 *  what Python would. Needs JSON.parse source access (Node >= 21); older
 *  Node falls back to plain parsing. */
function parseWithSources(line: string): Record<string, unknown> {
  return JSON.parse(line, function (this: unknown, _k: string, value: unknown, ctx?: { source?: string }) {
    if (typeof value === "number" && ctx && typeof ctx.source === "string") return new SourceNumber(ctx.source);
    return value;
  } as (this: unknown, key: string, value: unknown) => unknown);
}

export function hashEvent(body: Record<string, unknown>): string {
  return createHash("sha256").update(canonical(body), "utf8").digest("hex");
}

function now(): number {
  return Date.now() / 1000;
}

export class TraceStore {
  readonly root: string;

  constructor(root = "./traces") {
    this.root = root;
    fs.mkdirSync(root, { recursive: true });
  }

  private path(sessionId: string): string {
    return path.join(this.root, `${sessionId}.jsonl`);
  }

  createSession(name: string, metadata: Record<string, unknown> = {}): string {
    const d = new Date();
    const pad = (n: number) => String(n).padStart(2, "0");
    const stamp =
      `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-` +
      `${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
    const sessionId = `${stamp}-${randomBytes(4).toString("hex")}`;
    const header: Record<string, unknown> = {
      seq: 0, type: "session_start", ts: now(), session_id: sessionId,
      name, metadata, prev_hash: GENESIS,
    };
    header.hash = hashEvent(header);
    fs.writeFileSync(this.path(sessionId), toLine(header) + "\n", { flag: "wx" });
    return sessionId;
  }

  append(sessionId: string, eventType: string, payload: Record<string, unknown>): TraceEvent {
    const events = this.read(sessionId);
    const last = events[events.length - 1];
    const event: Record<string, unknown> = {
      seq: last.seq + 1, type: eventType, ts: now(), session_id: sessionId,
      payload, prev_hash: last.hash,
    };
    event.hash = hashEvent(event);
    fs.appendFileSync(this.path(sessionId), toLine(event) + "\n");
    return event as unknown as TraceEvent;
  }

  read(sessionId: string): TraceEvent[] {
    return fs.readFileSync(this.path(sessionId), "utf8")
      .split("\n").filter((l) => l.trim())
      .map((l) => JSON.parse(l) as TraceEvent);
  }

  verify(sessionId: string): VerificationResult {
    let prev = GENESIS;
    let count = 0;
    let lastType: unknown = null;
    const lines = fs.readFileSync(this.path(sessionId), "utf8").split("\n").filter((l) => l.trim());
    for (const line of lines) {
      let event: Record<string, unknown>, withSrc: Record<string, unknown>;
      try {
        event = JSON.parse(line);
        withSrc = parseWithSources(line);
      } catch {
        return { ok: false, events: count, firstBadSeq: count, reason: "malformed line (not valid JSON event)" };
      }
      const seq = event.seq as number;
      if (event.prev_hash !== prev) {
        return { ok: false, events: count, firstBadSeq: seq, reason: "chain broken (prev_hash mismatch)" };
      }
      const { hash, ...body } = withSrc;
      if (hashEvent(body) !== hash) {
        return { ok: false, events: count, firstBadSeq: seq, reason: "event content altered (hash mismatch)" };
      }
      prev = hash as string;
      count += 1;
      lastType = event.type;
    }
    if (count === 0) return { ok: false, events: 0, firstBadSeq: null, reason: "empty session" };
    return { ok: true, events: count, firstBadSeq: null, reason: null, sealed: lastType === "session_end" };
  }

  sessions(): Array<{ session_id: string; name: string; started: number; events: number; verified: boolean }> {
    return fs.readdirSync(this.root)
      .filter((f) => f.endsWith(".jsonl"))
      .sort().reverse()
      .map((f) => {
        const sid = f.replace(/\.jsonl$/, "");
        const events = this.read(sid);
        const head = events[0];
        return {
          session_id: sid, name: head.name ?? "", started: head.ts,
          events: events.length, verified: this.verify(sid).ok,
        };
      });
  }
}
