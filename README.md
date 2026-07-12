# flightrec ✈

**Flight recorder & forensics for AI agents.** Tamper-evident recording of everything your agent saw and did — prompts, model responses, tool calls — with a replay UI for incident investigation.

Over half of production AI agents run with no logging. When one leaks data or takes a harmful action, nobody can reconstruct why. flightrec is the black box.

## What it does

- **Records** LLM requests/responses and tool calls via a one-line SDK wrapper
- **Tamper-evident storage**: every event is SHA-256 hash-chained; any edit, deletion, or reordering of the log is detected
- **Flags** likely prompt-injection content in recorded traffic (heuristic, advisory)
- **Replays** sessions in a local web UI: timeline, event detail, integrity status, highlighted injection matches

## Quickstart

```bash
pip install -e ".[dev]"
python examples/demo_agent.py      # writes demo traces incl. a simulated injection incident
python -m flightrec.server         # open http://127.0.0.1:8377
```

## Instrument your own agent

```python
from flightrec import Recorder
from openai import OpenAI

rec = Recorder(root="./traces")
with rec.session("my-agent run") as s:
    client = s.wrap_openai(OpenAI())     # all .create() calls now recorded
    # or: client = s.wrap_anthropic(Anthropic())

    @s.record_tool
    def send_email(to: str, body: str):
        ...

    # use client and tools as normal
```

Verify integrity programmatically:

```python
from flightrec import TraceStore
v = TraceStore("./traces").verify(session_id)
print(v.ok, v.first_bad_seq, v.reason)
```

## Tests

```bash
pytest tests/
```

## Architecture

```
agent code ── Recorder SDK ──► TraceStore (hash-chained JSONL)
                                    │
                              scan.py (injection heuristics → _flags)
                                    │
                              server.py (FastAPI replay UI)
```

## MVP limitations / roadmap

- Local filesystem storage → next: S3/WORM object storage, external hash anchoring (e.g. periodic public timestamping)
- Heuristic injection flags only → next: model-based scanning, cross-event causal tracing ("which input caused which action")
- Sync Python SDK → next: async support, TypeScript SDK, OpenTelemetry-compatible export, MCP proxy capture mode
- No auth on the UI → next: SSO, RBAC, retention policies, chain-of-custody export (PDF) for regulators/insurers
