# flightrec ✈

**The black box for AI agents.** Tamper-evident recording of everything your agent saw and did — prompts, model responses, tool calls — with causal incident tracing, court-grade evidence export, and a replay UI.

Over half of production AI agents run with no logging. When one leaks data or takes a harmful action, nobody can reconstruct why. flightrec is the flight recorder: prevention tools assume attacks can be stopped; flightrec assumes some will land, and makes sure you can prove exactly what happened.

## Why it's different

- **Tamper-evident by construction** — every event is SHA-256 hash-chained; any edit, deletion, or reordering breaks verification from that point on
- **Externally anchored** — chain heads can be timestamped by an RFC 3161 authority, so even a wholesale rewrite of the chain after an incident is detectable
- **Causal, checkable evidence** — injection origins are linked to downstream actions via concrete tokens ("`attacker@evil.example` first appeared in this ticket, then in this `send_email` call"), never model guesswork
- **Verifiable by anyone** — evidence bundles include a stdlib-only `verify.py`; an auditor, insurer, or opposing counsel verifies offline with zero trust in you or us
- **Zero-code option** — the MCP proxy records any MCP-based agent with a one-line config change

## Install

```bash
pip install -e .                 # core (recording, replay UI, CLI)
pip install -e ".[dev]"          # + tests
pip install -e ".[anchor]"       # + RFC 3161 external timestamping
pip install -e ".[otel]"         # + OpenTelemetry export
```

## Quickstart (60 seconds)

```bash
python examples/demo_agent.py    # writes demo traces incl. a simulated injection incident
flightrec serve                  # replay UI at http://127.0.0.1:8377
```

The demo shows a clean session and an injection incident: red-flagged events, an incident panel tracing the poisoned ticket to the exfiltration email, and integrity badges that flip to TAMPERED if you edit a trace file by hand.

## Record your own agent

### SDK (3 lines)

```python
from flightrec import Recorder

rec = Recorder(root="./traces")
with rec.session("support-agent run", config={
    "system_prompt": "You are a support agent.",   # captured in the chain —
    "model": "claude-sonnet-5",                     # the most often-missing
    "tools": ["read_ticket", "send_email"],         # evidence in incidents
}) as s:
    client = s.wrap_openai(OpenAI())        # sync, async, and streaming all work
    # or: client = s.wrap_anthropic(Anthropic())

    @s.record_tool                          # sync or async tools
    def send_email(to: str, body: str): ...
```

Streaming responses are relayed chunk-by-chunk to your code while the assembled text is recorded as a single `llm_response`.

### TypeScript / Node (`js/`)

```ts
import { Recorder } from "flightrec";

const rec = new Recorder("./traces");
await rec.session("my-agent run", { config: { model: "gpt-x" } }, async (s) => {
  const client = s.wrapClient(new OpenAI());          // async + streaming recorded
  const sendEmail = s.recordTool("send_email", async (to: string) => { ... });
});
```

Traces are byte-compatible across languages: a session written from Node is verified, replayed, exported, and causally traced by the Python CLI.

### MCP proxy (0 lines)

Wrap any stdio MCP server in your client's config — Claude Desktop, Claude Code, or any framework:

```json
{ "command": "flightrec",
  "args": ["mcp-proxy", "--root", "/var/flightrec/traces", "--name", "github-mcp", "--",
           "npx", "-y", "@modelcontextprotocol/server-github"] }
```

All JSON-RPC traffic is relayed untouched and recorded; injection scanning and causal tracing apply automatically. Recording errors never break the agent.

## CLI

```
flightrec list                        sessions with integrity status + risk score
flightrec verify SESSION_ID | --all   verify hash chain + anchors (exit 1 on tamper — CI friendly)
flightrec serve                       replay UI
flightrec incident SESSION_ID         causal trace: injection origin -> downstream actions
flightrec export SESSION_ID           self-verifying evidence zip (chain of custody)
flightrec anchor SESSION_ID           RFC 3161 external timestamp of the chain head
flightrec otel SESSION_ID             export session as OpenTelemetry spans
```

### Example: incident trace

```
INCIDENT TRACE — session 20260718-154617-427bf6f0

origin seq 3 (tool_result) — verdicts: instruction override, concealment request, redirection — risk 29
  injected tokens: attacker@evil.example
  -> seq 5 llm_response            [TAINT: attacker@evil.example]
  -> seq 8 tool_call send_email    [TAINT: attacker@evil.example]
  (2 additional downstream event(s) with temporal link only)
```

Every link cites the exact token and where it appeared — an investigator can check each claim by hand, which is the standard evidence must meet.

### Example: evidence bundle

`flightrec export` produces `<session>_evidence.zip` containing the trace, a manifest (sha256, verification state, flagged events), and a dependency-free `verify.py`:

```
$ python verify.py
OK: events.jsonl sha256 matches manifest (a3f1c2...)
OK: hash chain intact across 10 events
EVIDENCE VERIFIED
```

## Threat model

| Attack | Defense |
|---|---|
| Edit/delete/reorder past events | Hash chain breaks at the exact seq — `verify` exit 1 |
| Rebuild the entire chain after an incident | External RFC 3161 anchor no longer matches |
| Dispute what config/model was live | Config snapshot is the first chained event |
| "The injection didn't cause that action" | Taint links cite the exact introduced token |
| Tamper with exported evidence | Standalone verifier fails; manifest sha256 mismatch |

Injection *flags* are advisory heuristics (severity-weighted: high/medium/low). The evidence trail is the product; detection is a lens over it.

## Architecture

```
agent code ── SDK wrappers ─┐
                            ├─► TraceStore (hash-chained JSONL) ──► anchors (RFC 3161)
MCP client ── mcp-proxy ────┘        │
                              scan.py (severity-weighted flags)
                              causal.py (taint analysis)
                                     │
                    ┌────────────────┼──────────────────┐
              server.py (UI)   export.py (evidence)   otel.py (spans)
```

## Tests

```bash
pytest tests/   # 19 tests: chain integrity, tamper/forgery detection, causal
                # tracing, MCP proxy end-to-end, async/streaming, OTel export
```

## Roadmap

- S3/WORM object storage backends and retention policies
- Chain-of-custody PDF reports for regulators and insurers
- UI auth (SSO/RBAC), multi-agent responsibility graphs
- Anomaly detection over the trace corpus — recording first, detection second
