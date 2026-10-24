# wakeprint 👣

**Every agent leaves a trail. wakeprint is the black box for AI agents.** Tamper-evident recording of everything your agent saw and did — prompts, model responses, tool calls — with causal incident tracing, court-grade evidence export, and a replay UI.

Over half of production AI agents run with no logging. When one leaks data or takes a harmful action, nobody can reconstruct why. wakeprint is the flight recorder: prevention tools assume attacks can be stopped; wakeprint assumes some will land, and makes sure you can prove exactly what happened.

> **Renamed from `echotrail`.** Versions 0.12–0.13 were published as `echotrail`. Replace `echotrail` with `wakeprint` in imports, CLI commands and MCP configs. The trace format is unchanged, so existing traces, anchors and evidence bundles still verify.

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
wakeprint serve                  # replay UI at http://127.0.0.1:8377
```

The demo shows a clean session and an injection incident: red-flagged events, an incident panel tracing the poisoned ticket to the exfiltration email, and integrity badges that flip to TAMPERED if you edit a trace file by hand.

## Record your own agent

### SDK (3 lines)

```python
from wakeprint import Recorder

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
import { Recorder } from "wakeprint";

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
{ "command": "wakeprint",
  "args": ["mcp-proxy", "--root", "/var/wakeprint/traces", "--name", "github-mcp", "--",
           "npx", "-y", "@modelcontextprotocol/server-github"] }
```

All JSON-RPC traffic is relayed untouched and recorded; injection scanning and causal tracing apply automatically. Recording errors never break the agent.

## CLI

```
wakeprint list                        sessions with integrity status + risk score
wakeprint verify SESSION_ID | --all   verify hash chain + anchors (exit 1 on tamper — CI friendly)
              [--tsa-ca CA.pem]       also check RFC 3161 token signatures (needs openssl)
wakeprint serve                       replay UI
wakeprint incident SESSION_ID         causal trace: injection origin -> downstream actions
wakeprint export SESSION_ID           self-verifying evidence zip (chain of custody)
wakeprint anchor SESSION_ID           RFC 3161 external timestamp of the chain head
wakeprint otel SESSION_ID             export session as OpenTelemetry spans
wakeprint siem SESSION_ID             ECS (default) or --format ocsf NDJSON for your SIEM
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

`wakeprint export` produces `<session>_evidence.zip` containing the trace, a manifest (sha256, verification state, flagged events), the session's anchor records, and a dependency-free `verify.py`:

```
$ python verify.py --tsa-ca freetsa_cacert.pem
OK: events.jsonl sha256 matches manifest (a3f1c2...)
OK: hash chain intact across 10 events
OK: RFC 3161 anchor matches chain head (TSA time 20260718154702Z, serial 157560240)
OK: TSA signature valid
EVIDENCE VERIFIED
```

Without `--tsa-ca`, the verifier still checks that each RFC 3161 token timestamps exactly the anchored hash (stdlib only); `--tsa-ca` with `openssl` on PATH also checks the TSA's signature. Get the TSA's CA certificate from the TSA itself, not from the bundle.

### SIEM export

`wakeprint siem SESSION_ID` writes one NDJSON record per event in Elastic Common Schema 8.11; `--format ocsf` writes OCSF 1.1 API Activity records plus a Detection Finding for every flagged event. Each record carries the event's `seq`, `hash`, `prev_hash`, the session's chain-verification result, and taint links back to the injection origin.

### Cross-language hashing

Event hashes use canonical JSON with ECMAScript number formatting (`2.0` → `2`, `1e-05` → `0.00001`), so a trace written from Node verifies in Python and vice versa, including payloads with floats. Traces written before v0.13 still verify in Python.

## Threat model

| Attack | Defense |
|---|---|
| Edit/delete/reorder past events | Hash chain breaks at the exact seq — `verify` exit 1 |
| Rebuild the entire chain after an incident | External RFC 3161 anchor no longer matches |
| Rebuild the chain *and* edit the anchor record | Token's signed imprint no longer matches the anchored hash |
| Fabricate a timestamp token | Signature check against the TSA's CA fails (`--tsa-ca`) |
| Concurrent writers (e.g. MCP proxy threads) | Per-session write lock keeps one linear chain |
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
