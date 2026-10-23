# echotrail 👣

**Every agent leaves a trail. echotrail is the black box for AI agents.** Tamper-evident recording of everything your agent saw and did — prompts, model responses, tool calls — with causal incident tracing, court-grade evidence export, and a replay UI.

Over half of production AI agents run with no logging. When one leaks data or takes a harmful action, nobody can reconstruct why. echotrail is the flight recorder: prevention tools assume attacks can be stopped; echotrail assumes some will land, and makes sure you can prove exactly what happened.

## Why it's different

- **Tamper-evident by construction** — every event is SHA-256 hash-chained; any edit, deletion, or reordering breaks verification from that point on
- **Externally anchored** — sealed sessions can be timestamped by an RFC 3161 authority; the signed token is verified against your own CA store, so even a wholesale rewrite of the chain after an incident is detectable
- **Causal, checkable evidence** — injection origins are linked to downstream actions via concrete tokens ("`attacker@evil.example` first appeared in this ticket, then in this `send_email` call"), never model guesswork
- **Verifiable by anyone** — evidence bundles include a standalone `verify.py` (Python stdlib + OpenSSL); for anchored sessions an auditor, insurer, or opposing counsel verifies offline with zero trust in you or us, and unanchored bundles are honestly reported as such
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
echotrail serve                  # replay UI at http://127.0.0.1:8377
```

The demo shows a clean session and an injection incident: red-flagged events, an incident panel tracing the poisoned ticket to the exfiltration email, and integrity badges that flip to TAMPERED if you edit a trace file by hand.

## Record your own agent

### SDK (3 lines)

```python
from echotrail import Recorder

rec = Recorder(root="./traces", anchor=True)   # anchor=True: RFC 3161-timestamp each sealed session
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
import { Recorder } from "echotrail";

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
{ "command": "echotrail",
  "args": ["mcp-proxy", "--root", "/var/echotrail/traces", "--name", "github-mcp", "--anchor", "--",
           "npx", "-y", "@modelcontextprotocol/server-github"] }
```

All JSON-RPC traffic is relayed untouched and recorded; injection scanning and causal tracing apply automatically. Recording errors never break the agent. Parallel tool calls are safe: appends are serialised per session, across threads and processes. `--anchor` timestamps the sealed session when the server exits.

## CLI

```
echotrail list                        sessions with integrity status (ok / unsealed / TAMPERED) + risk score
echotrail verify SESSION_ID | --all   verify hash chain + anchors (exit 1 on tamper, CI friendly)
                 [--tsa-ca FILE]      CA file trusted for timestamp tokens (default certifi / system store)
                 [--strict]           also fail on unsealed sessions and anchors that cannot be checked
echotrail serve                       replay UI
echotrail incident SESSION_ID         causal trace: injection origin -> downstream actions
echotrail export SESSION_ID           self-verifying evidence zip (chain of custody)
echotrail anchor SESSION_ID           RFC 3161 external timestamp of the chain head (default TSA: DigiCert)
echotrail otel SESSION_ID             export session as OpenTelemetry spans
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

`echotrail export` produces `<session>_evidence.zip` containing the trace, its RFC 3161 anchors, an informational manifest, and a standalone `verify.py` that needs only Python and OpenSSL:

```
$ python verify.py
OK: hash chain intact across 11 events
OK: session sealed (ends with session_end)
OK: anchor @seq 10 timestamped Oct 23 17:40:12 2026 GMT by DirName:/C=US/O=DigiCert, Inc./CN=<TSA responder>
EVIDENCE VERIFIED (chain intact and anchored by a trusted timestamp authority)
```

Exit codes: `0` verified and fully anchored, `2` internally consistent but not (fully) anchored, `1` failed. A bundle without anchors can only prove internal consistency: whoever exported it could have regenerated the chain and the manifest, so the verifier says `UNANCHORED` instead of `VERIFIED`. Timestamp tokens are checked against the auditor's own CA store, never a certificate shipped in the bundle.

## Threat model

| Attack | Defense |
|---|---|
| Edit/delete/reorder past events | Hash chain breaks at the exact seq, `verify` exit 1 |
| Cut events off the end, or append after the session closed | Session reported unsealed (no trailing `session_end`); `--strict` fails it; an anchor at seal time pins the final event |
| Rebuild the entire chain after an incident | RFC 3161 token no longer matches the chain (imprint mismatch) |
| Edit the anchor record or swap in another token | Token signature and imprint are verified against a trusted CA, so it fails |
| Forge an evidence bundle, manifest included | Anchored bundle: verifier fails. Anchors stripped: reported `UNANCHORED`, never `VERIFIED` |
| Dispute what config/model was live | Config snapshot is the first chained event |
| "The injection didn't cause that action" | Taint links cite the exact introduced token |

**Limits, stated plainly.** Without an anchor, a party holding the trace files can regenerate a whole session undetectably; hash chains prove consistency, not provenance. Deleting a session file outright leaves nothing to verify. Anchor every session (`anchor=True`, `--anchor`) and ship traces to write-once storage if either matters to you.

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
pytest tests/   # 39 tests: chain integrity, tamper/forgery detection, real RFC 3161
                # anchors (local test TSA via openssl), forged bundles, concurrent
                # writers, causal tracing, MCP proxy end-to-end, async/streaming,
                # OTel export, Node <-> Python trace compatibility
cd js && npm test
```

## Roadmap

- S3/WORM object storage backends and retention policies
- Per-writer signing keys, so a stolen trace directory cannot be extended
- Chain-of-custody PDF reports for regulators and insurers
- UI auth (SSO/RBAC), multi-agent responsibility graphs
- Anomaly detection over the trace corpus — recording first, detection second
