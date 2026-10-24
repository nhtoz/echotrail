"""End-to-end tests for wakeprint as installed from PyPI.

Run inside a clean venv where `pip install "wakeprint[anchor,otel]"` came
from PyPI, from this directory (see README.md). Nothing here imports the
repository's source tree; E01 fails if it does.
"""

import asyncio
import hashlib
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

import httpx
import httpx2
import pytest

import wakeprint
from wakeprint import Recorder, TraceStore
from wakeprint.causal import causal_analysis

from scripted_llm import ATTACKER, OBEY_TEXT, POISONED_TICKET, anthropic_handler, openai_handler

HERE = Path(__file__).parent
CLI = Path(sys.executable).parent / ("wakeprint.exe" if os.name == "nt" else "wakeprint")
FREETSA_CA = "https://freetsa.org/files/cacert.pem"

TOOL_SCHEMAS_ANTHROPIC = [
    {"name": "read_ticket", "description": "Read a ticket",
     "input_schema": {"type": "object", "properties": {"ticket_id": {"type": "string"}}}},
    {"name": "send_email", "description": "Send an email",
     "input_schema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}},
]
TOOL_SCHEMAS_OPENAI = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                          "parameters": t["input_schema"]}}
                       for t in TOOL_SCHEMAS_ANTHROPIC]
CONFIG = {"model": "claude-e2e", "system_prompt": "You are a support agent.", "tools": ["read_ticket", "send_email"]}


def cli(root, *args, **kw):
    return subprocess.run([str(CLI), "--root", str(root), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", **kw)


def tools(s):
    @s.record_tool
    def read_ticket(ticket_id: str) -> str:
        return POISONED_TICKET

    @s.record_tool
    def send_email(to: str, body: str) -> str:
        return f"sent to {to}"

    return {"read_ticket": read_ticket, "send_email": send_email}


def assert_incident(events, origin_type="tool_result"):
    """The poisoned ticket is flagged and taint-linked to the agent's actions."""
    incidents = [i for i in causal_analysis(events) if i["taint_hits"]]
    assert incidents, "injection origin should be traced"
    inc = incidents[0]
    assert inc["origin_type"] == origin_type and "instruction override" in inc["verdicts"]
    assert ATTACKER in inc["taint_tokens"]
    tainted = {(a["type"], a["tool"]) for a in inc["affected"] if a["link"] == "taint"}
    assert ("tool_call", "send_email") in tainted
    return inc


# -- E01 install ----------------------------------------------------------------------------

def test_e01_installed_from_pypi_not_source():
    site = Path(wakeprint.__file__).resolve()
    assert "site-packages" in site.parts, site
    from importlib.metadata import version, requires
    assert wakeprint.__version__ == version("wakeprint")
    expected = os.environ.get("WAKEPRINT_EXPECTED")  # set by CI to the version just published
    if expected:
        assert wakeprint.__version__ == expected
    reqs = " ".join(requires("wakeprint"))
    assert "rfc3161ng" in reqs and "opentelemetry-sdk" in reqs
    out = subprocess.run([str(CLI), "--help"], capture_output=True, text=True).stdout
    for cmd in ("list", "verify", "serve", "export", "anchor", "incident", "otel", "siem", "mcp-proxy"):
        assert cmd in out


# -- E02-E05 Anthropic SDK agents --------------------------------------------------------------

def anthropic_agent_loop(client, toolset):
    messages = [{"role": "user", "content": "Summarise ticket #4182"}]
    for _ in range(5):
        resp = client.messages.create(model="claude-e2e", max_tokens=256, tools=TOOL_SCHEMAS_ANTHROPIC,
                                      messages=messages)
        messages.append({"role": "assistant", "content": [b.model_dump(exclude_none=True) for b in resp.content]})
        if resp.stop_reason != "tool_use":
            return resp
        results = [{"type": "tool_result", "tool_use_id": b.id, "content": toolset[b.name](**b.input)}
                   for b in resp.content if b.type == "tool_use"]
        messages.append({"role": "user", "content": results})
    raise AssertionError("agent did not finish")


def test_e02_anthropic_tool_use_agent(tmp_path):
    import anthropic
    rec = Recorder(root=tmp_path)
    with rec.session("anthropic agent", config=CONFIG) as s:
        client = s.wrap_anthropic(anthropic.Anthropic(
            api_key="e2e", http_client=httpx2.Client(transport=httpx2.MockTransport(anthropic_handler))))
        final = anthropic_agent_loop(client, tools(s))
        assert final.content[0].text == "Ticket summarised."
    events = list(rec.store.read(s.session_id))
    types = [e["type"] for e in events]
    assert types[:2] == ["session_start", "config_snapshot"] and types[-1] == "session_end"
    assert types.count("llm_request") == 3 and types.count("llm_response") == 3
    assert types.count("tool_call") == 2 and types.count("tool_result") == 2
    flagged = [e for e in events[1:] if e.get("payload", {}).get("_flags")]
    assert any(e["type"] == "tool_result" for e in flagged)
    assert_incident(events)
    assert rec.store.verify(s.session_id).ok


def test_e03_anthropic_async_client_and_async_stream(tmp_path):
    import anthropic

    async def run(client):
        msg = await client.messages.create(model="claude-e2e", max_tokens=64,
                                           messages=[{"role": "user", "content": "hi"}])
        stream = await client.messages.create(model="claude-e2e", max_tokens=64, stream=True,
                                              messages=[{"role": "user", "content": "hi"}])
        n = 0
        async for _ in stream:
            n += 1
        return msg, n

    rec = Recorder(root=tmp_path)
    with rec.session("async") as s:
        client = s.wrap_anthropic(anthropic.AsyncAnthropic(
            api_key="e2e", http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(anthropic_handler))))
        msg, n = asyncio.run(run(client))
        assert msg.content[0].text == "Ticket summarised." and n > 3
    resps = [e for e in rec.store.read(s.session_id) if e["type"] == "llm_response"]
    assert len(resps) == 2
    assert resps[1]["payload"]["streamed"] and resps[1]["payload"]["response"]["content"] == OBEY_TEXT


def test_e04_anthropic_sync_stream_true(tmp_path):
    import anthropic
    rec = Recorder(root=tmp_path)
    with rec.session("stream") as s:
        client = s.wrap_anthropic(anthropic.Anthropic(
            api_key="e2e", http_client=httpx2.Client(transport=httpx2.MockTransport(anthropic_handler))))
        events = list(client.messages.create(model="claude-e2e", max_tokens=64, stream=True,
                                             messages=[{"role": "user", "content": "hi"}]))
        assert any(getattr(e, "type", "") == "message_stop" for e in events)
    resp = [e for e in rec.store.read(s.session_id) if e["type"] == "llm_response"][0]
    assert resp["payload"]["response"]["content"] == OBEY_TEXT
    # the assistant text echoes the injection, so the scanner-independent taint is visible later
    assert rec.store.verify(s.session_id).ok


def test_e05_anthropic_messages_stream_helper_sync_and_async(tmp_path):
    import anthropic
    rec = Recorder(root=tmp_path)
    with rec.session("stream helper") as s:
        sync_client = s.wrap_anthropic(anthropic.Anthropic(
            api_key="e2e", http_client=httpx2.Client(transport=httpx2.MockTransport(anthropic_handler))))
        with sync_client.messages.stream(model="claude-e2e", max_tokens=64,
                                         messages=[{"role": "user", "content": "hi"}]) as stream:
            text = "".join(stream.text_stream)
            final = stream.get_final_message()
        assert text == OBEY_TEXT and final.content[0].text == OBEY_TEXT

        async_client = s.wrap_anthropic(anthropic.AsyncAnthropic(
            api_key="e2e", http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(anthropic_handler))))

        async def run():
            async with async_client.messages.stream(model="claude-e2e", max_tokens=64,
                                                    messages=[{"role": "user", "content": "hi"}]) as st:
                return [e async for e in st]
        assert asyncio.run(run())
    events = list(rec.store.read(s.session_id))
    reqs = [e for e in events if e["type"] == "llm_request"]
    resps = [e for e in events if e["type"] == "llm_response"]
    assert len(reqs) == 2 and len(resps) == 2
    for r in resps:
        assert r["payload"]["streamed"] is True
        assert r["payload"]["response"]["content"][0]["text"] == OBEY_TEXT  # SDK's own snapshot
    assert rec.store.verify(s.session_id).ok


# -- E06 OpenAI SDK agent -------------------------------------------------------------------------

def test_e06_openai_tool_calling_agent_stream_and_async(tmp_path):
    import openai
    rec = Recorder(root=tmp_path)
    with rec.session("openai agent", config={**CONFIG, "model": "gpt-e2e"}) as s:
        client = s.wrap_openai(openai.OpenAI(
            api_key="e2e", http_client=httpx2.Client(transport=httpx2.MockTransport(openai_handler))))
        toolset = tools(s)
        messages = [{"role": "user", "content": "Summarise ticket #4182"}]
        for _ in range(5):
            resp = client.chat.completions.create(model="gpt-e2e", messages=messages, tools=TOOL_SCHEMAS_OPENAI)
            msg = resp.choices[0].message
            messages.append(msg.model_dump(exclude_none=True))
            if not msg.tool_calls:
                break
            for tc in msg.tool_calls:
                out = toolset[tc.function.name](**json.loads(tc.function.arguments))
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": out})
        assert msg.content == "Ticket summarised."

        chunks = list(client.chat.completions.create(model="gpt-e2e", stream=True,
                                                     messages=[{"role": "user", "content": "hi"}]))
        assert len(chunks) == len(OBEY_TEXT.split(" "))

        aclient = s.wrap_openai(openai.AsyncOpenAI(
            api_key="e2e", http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(openai_handler))))
        r = asyncio.run(aclient.chat.completions.create(model="gpt-e2e",
                                                        messages=[{"role": "user", "content": "hi"}]))
        assert r.choices[0].message.content == "Ticket summarised."
    events = list(rec.store.read(s.session_id))
    streamed = [e for e in events if e["type"] == "llm_response" and e["payload"].get("streamed")]
    assert streamed and streamed[0]["payload"]["response"]["content"] == OBEY_TEXT
    assert_incident(events)
    assert rec.store.verify(s.session_id).ok


# -- E07 MCP agent through the zero-code proxy ---------------------------------------------------------

def test_e07_mcp_agent_through_proxy(tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    root = tmp_path / "traces"
    params = StdioServerParameters(
        command=str(CLI),
        args=["--root", str(root), "mcp-proxy", "--name", "e2e-mcp", "--",
              sys.executable, str(HERE / "mcp_ticket_server.py")])

    async def agent():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                ticket = await session.call_tool("read_ticket", {"ticket_id": "4182"})
                sent = await session.call_tool("send_email", {"to": ATTACKER, "body": "customer_records.csv"})
                return [t.name for t in listed.tools], ticket.content[0].text, sent.content[0].text

    names, ticket, sent = asyncio.run(agent())
    assert set(names) == {"read_ticket", "send_email"}
    assert ATTACKER in ticket and sent == f"sent to {ATTACKER}"  # relayed untouched

    deadline = time.time() + 15
    while time.time() < deadline:  # the proxy logs its exit event as it shuts down
        sessions = TraceStore(root).sessions()
        if sessions and any(e["type"] == "mcp_proxy_exit" for e in TraceStore(root).read(sessions[0]["session_id"])):
            break
        time.sleep(0.3)
    store = TraceStore(root)
    sid = store.sessions()[0]["session_id"]
    events = list(store.read(sid))
    types = [e["type"] for e in events]
    assert types.count("tool_call") == 2 and types.count("tool_result") == 2
    assert "mcp_request" in types and store.verify(sid).ok
    assert_incident(events)


# -- E08 CLI workflow on a recorded agent session ---------------------------------------------------------

@pytest.fixture
def agent_session(tmp_path):
    import anthropic
    root = tmp_path / "traces"
    rec = Recorder(root=root)
    with rec.session("support-agent", config=CONFIG) as s:
        client = s.wrap_anthropic(anthropic.Anthropic(
            api_key="e2e", http_client=httpx2.Client(transport=httpx2.MockTransport(anthropic_handler))))
        anthropic_agent_loop(client, tools(s))
    return root, s.session_id


def test_e08_cli_list_verify_incident_siem_otel(agent_session, tmp_path):
    root, sid = agent_session
    r = cli(root, "list")
    assert r.returncode == 0 and sid in r.stdout and "ok" in r.stdout and "risk=" in r.stdout
    r = cli(root, "verify", sid)
    assert r.returncode == 0 and "chain intact" in r.stdout
    r = cli(root, "incident", sid)
    assert r.returncode == 0 and "INCIDENT TRACE — session" in r.stdout  # UTF-8 when piped
    taint_lines = [l for l in r.stdout.splitlines() if "tool_call send_email  [TAINT: " in l]
    assert taint_lines and ATTACKER in taint_lines[0]
    for fmt in ("ecs", "ocsf"):
        out = tmp_path / f"s.{fmt}.ndjson"
        r = cli(root, "siem", sid, "--format", fmt, "-o", str(out))
        assert r.returncode == 0, r.stderr
        recs = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        assert recs
    r = cli(root, "otel", sid)
    assert r.returncode == 0 and "exported" in r.stdout


# -- E09 tamper matrix --------------------------------------------------------------------------------------

def _mutate(root, sid, fn):
    p = Path(root) / f"{sid}.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(fn(lines)) + "\n", encoding="utf-8")


def _edit(lines):
    i = next(i for i, l in enumerate(lines) if '"tool_result"' in l)
    e = json.loads(lines[i]); e["payload"]["result"] = "harmless ticket"; lines[i] = json.dumps(e)
    return lines


@pytest.mark.parametrize("name,fn,caught", [
    ("edit", _edit, True),
    ("delete-middle", lambda l: l[:3] + l[4:], True),
    ("reorder", lambda l: l[:3] + [l[4], l[3]] + l[5:], True),
    ("truncate-tail", lambda l: l[:-3], False),  # documented limit: needs an anchor
])
def test_e09_tamper_matrix_cli_verify(agent_session, name, fn, caught):
    root, sid = agent_session
    _mutate(root, sid, fn)
    r = cli(root, "verify", sid)
    assert (r.returncode == 1) == caught, (name, r.stdout)
    if caught:
        assert "TAMPER DETECTED at seq" in r.stdout


def _rewrite_chain(root, sid, change):
    from wakeprint.canonical import canonical
    p = Path(root) / f"{sid}.jsonl"
    events = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]
    change(events)
    prev = "0" * 64
    for e in events:
        e["prev_hash"] = prev
        e["hash"] = hashlib.sha256(canonical({k: v for k, v in e.items() if k != "hash"})).hexdigest()
        prev = e["hash"]
    p.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return prev


# -- E10/E11 anchoring + evidence bundles (live freetsa.org) -----------------------------------------------

@pytest.fixture(scope="session")
def freetsa_ca(tmp_path_factory):
    path = tmp_path_factory.mktemp("ca") / "freetsa_cacert.pem"
    try:
        urllib.request.urlretrieve(FREETSA_CA, path)
    except Exception as e:
        pytest.skip(f"cannot download freetsa CA: {e}")
    return path


def test_e10_live_rfc3161_anchor_signature_and_rewrite_detection(agent_session, freetsa_ca):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not on PATH")
    root, sid = agent_session
    r = cli(root, "anchor", sid)
    assert r.returncode == 0 and "via rfc3161" in r.stdout, r.stdout + r.stderr
    r = cli(root, "verify", sid, "--tsa-ca", str(freetsa_ca))
    assert r.returncode == 0 and "signature valid" in r.stdout, r.stdout

    # truncating the tail is now caught, because the anchored seq is gone
    _mutate(root, sid, lambda l: l[:-2])
    r = cli(root, "verify", sid)
    assert r.returncode == 1 and "MISMATCH" in r.stdout


def test_e11_full_rewrite_and_forged_anchor_record(agent_session):
    root, sid = agent_session
    r = cli(root, "anchor", sid)
    assert "via rfc3161" in r.stdout, r.stdout + r.stderr

    def change(events):
        for e in events:
            if e["type"] == "tool_call" and e["payload"].get("tool") == "send_email":
                e["payload"]["kwargs"]["to"] = "customer@example.com"
    head = _rewrite_chain(root, sid, change)
    r = cli(root, "verify", sid)
    assert r.returncode == 1 and "chain intact" in r.stdout and "MISMATCH" in r.stdout  # chain ok, anchor not

    af = next((Path(root) / "anchors").glob(f"{sid}.*.json"))
    a = json.loads(af.read_text()); a["anchored_hash"] = head
    af.write_text(json.dumps(a))
    r = cli(root, "verify", sid)
    assert r.returncode == 1 and "does not timestamp the anchored hash" in r.stdout


def test_e12_evidence_bundle_offline_verification(agent_session, tmp_path, freetsa_ca):
    root, sid = agent_session
    assert "via rfc3161" in cli(root, "anchor", sid).stdout
    r = cli(root, "export", sid, "-o", str(tmp_path / "out"))
    assert r.returncode == 0
    zip_path = next((tmp_path / "out").glob("*_evidence.zip"))
    x = tmp_path / "auditor"
    zipfile.ZipFile(zip_path).extractall(x)
    names = sorted(p.relative_to(x).as_posix() for p in x.rglob("*") if p.is_file())
    assert {"events.jsonl", "manifest.json", "verify.py", "README.txt"} <= set(names)
    assert any(n.startswith("anchors/") for n in names)

    # an auditor's plain Python: isolated mode, no site-packages, no wakeprint
    base = getattr(sys, "_base_executable", sys.executable)
    check = subprocess.run([base, "-I", "-S", "-c", "import wakeprint"], capture_output=True)
    assert check.returncode != 0, "auditor interpreter must not see wakeprint"

    def audit(*extra):
        return subprocess.run([base, "-I", "-S", str(x / "verify.py"), *extra], capture_output=True,
                              text=True, cwd=x)
    ok = audit()
    assert ok.returncode == 0, ok.stdout
    assert "OK: RFC 3161 anchor matches chain head" in ok.stdout and "EVIDENCE VERIFIED" in ok.stdout
    if shutil.which("openssl"):
        signed = audit("--tsa-ca", str(freetsa_ca))
        assert signed.returncode == 0 and "OK: TSA signature valid" in signed.stdout, signed.stdout

    ev = x / "events.jsonl"
    lines = ev.read_text(encoding="utf-8").splitlines()
    e = json.loads(lines[2]); e["payload"]["model"] = "other-model"; lines[2] = json.dumps(e)
    ev.write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = audit()
    assert bad.returncode == 1 and "FAIL" in bad.stdout


# -- E13 SIEM content ----------------------------------------------------------------------------------------

def test_e13_siem_ecs_and_ocsf_content(agent_session):
    from wakeprint.siem import export_records
    root, sid = agent_session
    store = TraceStore(root)
    ecs = list(export_records(store, sid, "ecs"))
    alerts = [r for r in ecs if r["event"]["kind"] == "alert"]
    assert alerts and alerts[0]["rule"]["name"] == "instruction override"
    send = [r for r in ecs if r["wakeprint"].get("tool") == "send_email"
            and r["event"]["action"] == "tool_call"]
    assert send and send[0]["wakeprint"]["taint_origin_seqs"] == [alerts[0]["event"]["sequence"]]
    assert all(r["wakeprint"]["chain_verified"] for r in ecs)
    ocsf = list(export_records(store, sid, "ocsf"))
    findings = [r for r in ocsf if r["class_uid"] == 2004]
    assert len(findings) == len(alerts) and findings[0]["severity_id"] == 4
    assert all(r["type_uid"] == r["class_uid"] * 100 + r["activity_id"] for r in ocsf)


# -- E14 OpenTelemetry over real OTLP/HTTP -------------------------------------------------------------------

def test_e14_otel_otlp_http_export_to_collector(agent_session):
    root, sid = agent_session
    received = []

    class Collector(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.headers.get("Content-Type"),
                             self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200); self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Collector)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = cli(root, "otel", sid, "--endpoint", f"http://127.0.0.1:{srv.server_port}/v1/traces")
        assert r.returncode == 0, r.stderr
    finally:
        srv.shutdown()
    assert received and received[0][0] == "/v1/traces" and "protobuf" in received[0][1]
    body = b"".join(b for _, _, b in received)
    assert b"tool read_ticket" in body and b"wakeprint.flagged" in body


# -- E15 replay UI ----------------------------------------------------------------------------------------------

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_e15_replay_ui_api_and_path_traversal(agent_session, tmp_path):
    root, sid = agent_session
    secret = Path(root).parent / "outside.jsonl"
    secret.write_text(json.dumps({"seq": 0, "type": "session_start", "ts": 0, "session_id": "x",
                                  "name": "SECRET-OUTSIDE-ROOT", "metadata": {}, "prev_hash": "0" * 64,
                                  "hash": "0" * 64}) + "\n")
    port = _free_port()
    proc = subprocess.Popen([str(CLI), "--root", str(root), "serve", "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                httpx.get(base + "/api/sessions", timeout=1)
                break
            except httpx.HTTPError:
                time.sleep(0.25)
        sessions = httpx.get(base + "/api/sessions").json()
        assert sessions[0]["session_id"] == sid and sessions[0]["verified"] is True and sessions[0]["risk"] > 0
        detail = httpx.get(f"{base}/api/sessions/{sid}").json()
        assert detail["verification"]["ok"] and detail["incidents"][0]["taint_hits"] >= 1
        page = httpx.get(base + "/")
        assert page.status_code == 200 and "wakeprint" in page.text
        assert httpx.get(base + "/api/sessions/does-not-exist").status_code == 404
        for probe in ("..%5Coutside", "..%2Foutside", "..%255Coutside"):
            r = httpx.get(f"{base}/api/sessions/{probe}")
            assert "SECRET-OUTSIDE-ROOT" not in r.text, f"path traversal via {probe}: {r.status_code}"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# -- E16 concurrency ------------------------------------------------------------------------------------------------

def test_e16_concurrent_writers(tmp_path):
    rec = Recorder(root=tmp_path)
    with rec.session("load") as s:
        def worker(n):
            for i in range(250):
                s.log("tool_call", tool=f"worker{n}", i=i)
        ts = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    events = list(rec.store.read(s.session_id))
    assert len(events) == 2002 and [e["seq"] for e in events] == list(range(2002))
    assert rec.store.verify(s.session_id).ok


# -- E17 Node agent, verified by the Python CLI ------------------------------------------------------

def test_e17_node_trace_verified_by_python_cli(tmp_path):
    sdk = os.environ.get("WAKEPRINT_NODE_SDK")  # path to a built js/build/src/index.js
    runner = shutil.which("node") or shutil.which("bun")
    if not sdk or not runner:
        pytest.skip("set WAKEPRINT_NODE_SDK and install node or bun")
    run = subprocess.run([runner, str(HERE / "node_agent.mjs"), sdk, str(tmp_path)],
                         capture_output=True, text=True, check=True)
    sid = run.stdout.strip().splitlines()[-1]
    r = cli(tmp_path, "verify", sid)
    assert r.returncode == 0 and "chain intact" in r.stdout, r.stdout
    r = cli(tmp_path, "incident", sid)
    taint = [l for l in r.stdout.splitlines() if "tool_call send_email  [TAINT: " in l]
    assert taint and ATTACKER in taint[0]
    # the Node SDK wrote these floats in JavaScript's format; Python must hash them the same way
    raw = (tmp_path / f"{sid}.jsonl").read_text(encoding="utf-8")
    assert '"score":0.00001' in raw and '"ratio":2' in raw
