# End-to-end tests

These tests check **the package as published on PyPI**, not the code in this repository. They install `wakeprint` from PyPI into a clean environment and drive it the way a user's agent would.

They run automatically after every publish (the `e2e` job in [`.github/workflows/publish.yml`](../.github/workflows/publish.yml)). The repository's unit tests live in [`tests/`](../tests).

## What's covered

| ID | Scenario |
|---|---|
| E01 | Installed from PyPI, not from source; CLI commands present |
| E02 | Anthropic tool-use agent: poisoned ticket flagged and traced to `send_email` |
| E03 | Anthropic async client and async streaming |
| E04 | Anthropic `stream=True` |
| E05 | Anthropic `messages.stream()`, sync and async |
| E06 | OpenAI tool-calling agent, streaming and async |
| E07 | Real MCP client and server through `wakeprint mcp-proxy` |
| E08 | CLI: `list`, `verify`, `incident`, `siem`, `otel`; UTF-8 when piped |
| E09 | Tamper matrix: edit, delete, reorder caught; tail truncation needs an anchor |
| E10 | Live RFC 3161 anchor from freetsa.org, signature checked against its CA |
| E11 | Full chain rewrite, and a forged anchor record, both caught |
| E12 | Evidence bundle verified offline by a bare Python interpreter |
| E13 | ECS and OCSF content |
| E14 | OpenTelemetry export over OTLP/HTTP to a local collector |
| E15 | Replay UI API, including path traversal probes |
| E16 | 8 threads writing 2,000 events to one session |
| E17 | Node SDK agent's trace verified by the Python CLI |

**How agents run.** The official `anthropic`, `openai` and `mcp` SDKs are used unmodified. For the LLM SDKs only the HTTP transport is replaced, by [`scripted_llm.py`](scripted_llm.py): a scripted model that answers with real API-shaped JSON and server-sent events and replays the demo incident (the agent reads a poisoned ticket and emails customer records to `attacker@evil.example`). No API keys are needed. [`mcp_ticket_server.py`](mcp_ticket_server.py) is a real MCP server with the same poisoned tool.

## Running locally

Run from **this directory** with the `pytest` command, so the repository root isn't on `sys.path` (E01 fails if `wakeprint` is imported from source):

```bash
python -m venv .venv-e2e
.venv-e2e/bin/pip install "wakeprint[anchor,otel]" anthropic openai mcp httpx pytest   # Scripts\pip on Windows
cd e2e
../.venv-e2e/bin/pytest -v
```

Requirements and options:

- Python 3.11 or newer (the current Anthropic and OpenAI SDKs need it).
- E10 and E12 need internet access to freetsa.org; E10 also needs `openssl` on `PATH`, and E12 checks the TSA signature only when it is.
- `WAKEPRINT_EXPECTED=0.14.1` makes E01 also check the installed version.
- E17 runs when `WAKEPRINT_NODE_SDK` points to a built `js/build/src/index.js` and `node` or `bun` is installed; it is skipped otherwise.
