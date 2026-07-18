/**
 * Recorder SDK for TypeScript/Node agents.
 *
 *   import { Recorder } from "flightrec";
 *
 *   const rec = new Recorder("./traces");
 *   await rec.session("my-agent run", { config: { model: "gpt-x" } }, async (s) => {
 *     const client = s.wrapClient(new OpenAI(), "openai");
 *     const sendEmail = s.recordTool("send_email", async (to: string) => {...});
 *     // use client and tools as normal — everything is traced
 *   });
 */
import { scanPayload, riskScore } from "./scan.js";
import { TraceStore } from "./store.js";

type AnyFn = (...args: unknown[]) => unknown;

function safe(obj: unknown, depth = 0): unknown {
  if (depth > 6) return String(obj);
  if (obj === null || ["boolean", "number", "string"].includes(typeof obj)) return obj;
  if (obj === undefined) return null;
  if (Array.isArray(obj)) return obj.map((v) => safe(v, depth + 1));
  if (typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (typeof v !== "function") out[k] = safe(v, depth + 1);
    }
    return out;
  }
  return String(obj);
}

function deltaText(chunk: unknown): string {
  const d = safe(chunk) as Record<string, unknown> | null;
  if (!d || typeof d !== "object") return "";
  const choices = d["choices"];
  if (Array.isArray(choices) && choices[0] && typeof choices[0] === "object") {
    const delta = (choices[0] as Record<string, unknown>)["delta"];
    if (delta && typeof delta === "object") {
      const c = (delta as Record<string, unknown>)["content"];
      if (typeof c === "string") return c;
    }
  }
  const delta = d["delta"];
  if (delta && typeof delta === "object") {
    const t = (delta as Record<string, unknown>)["text"];
    if (typeof t === "string") return t;
  }
  return "";
}

export class Session {
  constructor(readonly store: TraceStore, readonly sessionId: string) {}

  log(eventType: string, payload: Record<string, unknown>): void {
    const clean = safe(payload) as Record<string, unknown>;
    const findings = scanPayload(clean);
    if (findings.length > 0) {
      clean._flags = findings as unknown as Record<string, unknown>[];
      clean._risk = riskScore(findings);
    }
    this.store.append(this.sessionId, eventType, clean);
  }

  snapshotConfig(config: Record<string, unknown>): void {
    this.log("config_snapshot", config);
  }

  /** Wrap a tool function (sync or async); calls and results are recorded. */
  recordTool<T extends AnyFn>(name: string, fn: T): T {
    const session = this;
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
      session.log("tool_call", { tool: name, args: safe(args) as unknown[] });
      let result: unknown;
      try {
        result = fn.apply(this, args);
      } catch (e) {
        session.log("tool_error", { tool: name, error: String(e) });
        throw e;
      }
      if (result instanceof Promise) {
        return result.then(
          (r) => { session.log("tool_result", { tool: name, result: safe(r) }); return r; },
          (e) => { session.log("tool_error", { tool: name, error: String(e) }); throw e; },
        );
      }
      session.log("tool_result", { tool: name, result: safe(result) });
      return result;
    };
    return wrapped as T;
  }

  /** Proxy an LLM client (OpenAI/Anthropic JS SDKs): every `.create()` is recorded,
   *  including async and streaming responses. */
  wrapClient<T extends object>(client: T, provider = "openai"): T {
    const session = this;
    const makeProxy = (target: object): object =>
      new Proxy(target, {
        get(t, prop, receiver) {
          const value = Reflect.get(t, prop, receiver);
          if (prop === "create" && typeof value === "function") {
            return async (kwargs: Record<string, unknown>) => {
              session.log("llm_request", { provider, request: safe(kwargs) as Record<string, unknown> });
              const response = await (value as AnyFn).call(t, kwargs);
              if (response && typeof response === "object" && Symbol.asyncIterator in response) {
                return session.recordStream(response as AsyncIterable<unknown>, provider);
              }
              session.log("llm_response", { provider, response: safe(response) });
              return response;
            };
          }
          if (typeof value === "function") return value.bind(t);
          if (value !== null && typeof value === "object") return makeProxy(value);
          return value;
        },
      });
    return makeProxy(client) as T;
  }

  /** Relay a streaming response chunk-by-chunk; log assembled text at the end. */
  async *recordStream(stream: AsyncIterable<unknown>, provider = "openai"): AsyncGenerator<unknown> {
    const parts: string[] = [];
    let chunks = 0;
    try {
      for await (const chunk of stream) {
        chunks += 1;
        parts.push(deltaText(chunk));
        yield chunk;
      }
    } finally {
      this.log("llm_response", {
        provider, streamed: true, chunk_count: chunks,
        response: { content: parts.join("") },
      });
    }
  }
}

export class Recorder {
  readonly store: TraceStore;

  constructor(root = "./traces") {
    this.store = new TraceStore(root);
  }

  /** Run `fn` inside a recorded session; session_end is always written. */
  async session<R>(
    name: string,
    opts: { metadata?: Record<string, unknown>; config?: Record<string, unknown> },
    fn: (s: Session) => R | Promise<R>,
  ): Promise<R> {
    const sessionId = this.store.createSession(name, opts.metadata ?? {});
    const s = new Session(this.store, sessionId);
    if (opts.config) s.snapshotConfig(opts.config);
    try {
      const result = await fn(s);
      s.log("session_end", { status: "ok" });
      return result;
    } catch (e) {
      s.log("session_end", { status: "error", error: String(e) });
      throw e;
    }
  }
}
