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
}

/** Canonical JSON: recursively sorted keys, compact separators — matches
 *  Python's json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False). */
export function canonical(obj: unknown): string {
  return JSON.stringify(sortKeys(obj));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as object).sort()) {
      out[k] = sortKeys((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
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
    fs.writeFileSync(this.path(sessionId), JSON.stringify(header) + "\n");
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
    fs.appendFileSync(this.path(sessionId), JSON.stringify(event) + "\n");
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
    for (const event of this.read(sessionId)) {
      const { hash, ...body } = event;
      if (event.prev_hash !== prev) {
        return { ok: false, events: count, firstBadSeq: event.seq, reason: "chain broken (prev_hash mismatch)" };
      }
      if (hashEvent(body as Record<string, unknown>) !== hash) {
        return { ok: false, events: count, firstBadSeq: event.seq, reason: "event content altered (hash mismatch)" };
      }
      prev = hash;
      count += 1;
    }
    return { ok: true, events: count, firstBadSeq: null, reason: null };
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
