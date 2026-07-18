"""Replay & forensics web UI.

Run:  python -m flightrec.server --root ./traces --port 8377
Then open http://127.0.0.1:8377
"""

from __future__ import annotations

import argparse
import json

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from .causal import causal_analysis
from .store import TraceStore

app = FastAPI(title="flightrec")
_store: TraceStore | None = None


def get_store() -> TraceStore:
    global _store
    if _store is None:
        _store = TraceStore("./traces")
    return _store


@app.get("/api/sessions")
def sessions() -> JSONResponse:
    return JSONResponse(get_store().sessions())


@app.get("/api/sessions/{session_id}")
def session_detail(session_id: str) -> JSONResponse:
    store = get_store()
    try:
        events = list(store.read(session_id))
    except FileNotFoundError:
        raise HTTPException(404, "session not found")
    v = store.verify(session_id)
    return JSONResponse(
        {
            "events": events,
            "verification": {
                "ok": v.ok,
                "events": v.events,
                "first_bad_seq": v.first_bad_seq,
                "reason": v.reason,
            },
            "incidents": causal_analysis(events),
        }
    )


PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>flightrec — agent flight recorder</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --line:#30363d; --text:#e6edf3; --dim:#8b949e;
          --ok:#3fb950; --bad:#f85149; --warn:#d29922; --acc:#58a6ff; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 ui-monospace,Menlo,Consolas,monospace; background:var(--bg); color:var(--text); }
  header { padding:12px 20px; border-bottom:1px solid var(--line); display:flex; gap:12px; align-items:baseline; }
  header h1 { font-size:16px; margin:0; } header span { color:var(--dim); font-size:12px; }
  .wrap { display:flex; height:calc(100vh - 49px); }
  #list { width:320px; border-right:1px solid var(--line); overflow-y:auto; }
  .sess { padding:12px 16px; border-bottom:1px solid var(--line); cursor:pointer; }
  .sess:hover, .sess.active { background:var(--panel); }
  .sess .name { color:var(--acc); }
  .sess .meta { color:var(--dim); font-size:12px; }
  #main { flex:1; overflow-y:auto; padding:20px; }
  .badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:12px; }
  .badge.ok { background:#12261e; color:var(--ok); border:1px solid var(--ok); }
  .badge.bad { background:#2d1214; color:var(--bad); border:1px solid var(--bad); }
  .event { border:1px solid var(--line); border-radius:8px; margin-bottom:10px; background:var(--panel); }
  .event.flagged { border-color:var(--bad); }
  .ehead { padding:8px 14px; display:flex; gap:12px; align-items:center; cursor:pointer; }
  .etype { font-weight:bold; }
  .t-llm_request .etype { color:var(--acc); } .t-llm_response .etype { color:#bc8cff; }
  .t-config_snapshot .etype { color:#79c0ff; }
  .t-tool_call .etype { color:var(--warn); } .t-tool_result .etype { color:var(--ok); }
  .t-tool_error .etype, .t-session_end.err .etype { color:var(--bad); }
  .eseq { color:var(--dim); width:44px; } .ets { color:var(--dim); font-size:12px; margin-left:auto; }
  .flag { background:#2d1214; color:var(--bad); border:1px solid var(--bad); border-radius:4px;
          padding:1px 8px; font-size:11px; margin-left:6px; }
  .flag.sev-medium { background:#2b2111; color:var(--warn); border-color:var(--warn); }
  .flag.sev-low { background:#1c2416; color:#9ccc65; border-color:#9ccc65; }
  .risk { display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px;
          background:#2d1214; color:var(--bad); border:1px solid var(--bad); }
  .incident { border:1px solid var(--bad); border-radius:8px; background:#1a0f10;
              padding:10px 14px; margin-bottom:14px; }
  .incident h3 { margin:0 0 6px; font-size:13px; color:var(--bad); }
  .incident .arrow { color:var(--dim); }
  .incident .taint { color:#ffdcd7; }
  .incident .tok { background:#67060c; border-radius:3px; padding:0 4px; }
  .event.tainted { border-color:var(--warn); }
  .ebody { display:none; padding:0 14px 12px; }
  .event.open .ebody { display:block; }
  pre { background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:10px;
        white-space:pre-wrap; word-break:break-word; max-height:400px; overflow-y:auto; margin:6px 0; }
  mark { background:#67060c; color:#ffdcd7; border-radius:3px; padding:0 2px; }
  .empty { color:var(--dim); padding:60px; text-align:center; }
</style>
</head>
<body>
<header><h1>&#9992; flightrec</h1><span>agent flight recorder &amp; forensics — MVP</span></header>
<div class="wrap">
  <div id="list"></div>
  <div id="main"><div class="empty">Select a session to replay it.</div></div>
</div>
<script>
let current = null;

async function loadSessions() {
  const r = await fetch('/api/sessions'); const data = await r.json();
  const el = document.getElementById('list');
  el.innerHTML = data.map(s => `
    <div class="sess" data-id="${s.session_id}" onclick="openSession('${s.session_id}')">
      <div class="name">${esc(s.name || s.session_id)}</div>
      <div class="meta">${new Date(s.started*1000).toLocaleString()} · ${s.events} events ·
        <span class="badge ${s.verified ? 'ok':'bad'}">${s.verified ? 'integrity ok':'TAMPERED'}</span>
        ${s.risk ? `<span class="risk">risk ${s.risk}</span>` : ''}
      </div>
    </div>`).join('') || '<div class="empty">No sessions yet.</div>';
}

async function openSession(id) {
  current = id;
  document.querySelectorAll('.sess').forEach(e => e.classList.toggle('active', e.dataset.id === id));
  const r = await fetch('/api/sessions/' + id); const data = await r.json();
  const v = data.verification;
  const vbadge = v.ok
    ? `<span class="badge ok">chain verified — ${v.events} events intact</span>`
    : `<span class="badge bad">TAMPER DETECTED at seq ${v.first_bad_seq}: ${esc(v.reason)}</span>`;
  const flagged = data.events.filter(e => e.payload && e.payload._flags).length;
  const totalRisk = data.events.reduce((a,e) => a + ((e.payload && e.payload._risk) || 0), 0);
  const fnote = flagged
    ? ` <span class="badge bad">${flagged} flagged event(s)</span> <span class="risk">session risk ${totalRisk}</span>`
    : '';
  const taintedSeqs = new Set();
  (data.incidents || []).forEach(i => i.affected.forEach(a => { if (a.link === 'taint') taintedSeqs.add(a.seq); }));
  const incidentsHtml = (data.incidents || []).filter(i => i.taint_hits > 0).map(i => `
    <div class="incident">
      <h3>&#9888; Incident: injection at seq ${i.origin_seq} (risk ${i.risk})</h3>
      <div>verdicts: ${i.verdicts.map(esc).join(', ')}</div>
      ${i.taint_tokens.length ? `<div>injected tokens: ${i.taint_tokens.map(t => `<span class="tok">${esc(t)}</span>`).join(' ')}</div>` : ''}
      ${i.affected.filter(a => a.link === 'taint').map(a =>
        `<div class="taint"><span class="arrow">&#8627;</span> seq ${a.seq} ${esc(a.type)}${a.tool ? ' · ' + esc(a.tool) : ''}
         — evidence: ${a.evidence.map(t => `<span class="tok">${esc(t)}</span>`).join(' ')}</div>`).join('')}
    </div>`).join('');
  document.getElementById('main').innerHTML =
    `<div style="margin-bottom:16px">${vbadge}${fnote}</div>` + incidentsHtml +
    data.events.map(e => renderEvent(e, taintedSeqs)).join('');
}

function renderEvent(e, taintedSeqs) {
  const flags = (e.payload && e.payload._flags) || [];
  const tainted = taintedSeqs && taintedSeqs.has(e.seq);
  const flagHtml = flags.map(f =>
    `<span class="flag sev-${esc(f.severity || 'high')}">&#9873; ${esc(f.label)} · ${esc(f.severity || '')} ${f.weight ? '+'+f.weight : ''}</span>`).join('');
  const ts = new Date(e.ts*1000).toLocaleTimeString();
  let body = JSON.stringify(e.payload ?? {name:e.name, metadata:e.metadata}, null, 2);
  body = esc(body);
  for (const f of flags) {
    const m = esc(f.match).replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
    try { body = body.replace(new RegExp(m, 'gi'), x => `<mark>${x}</mark>`); } catch(_) {}
  }
  return `<div class="event t-${e.type} ${flags.length ? 'flagged':''} ${tainted ? 'tainted':''}" onclick="this.classList.toggle('open')">
    <div class="ehead"><span class="eseq">#${e.seq}</span><span class="etype">${e.type}</span>
      ${flagHtml}${tainted ? '<span class="flag sev-medium">&#8627; tainted by injection</span>' : ''}<span class="ets">${ts}</span></div>
    <div class="ebody"><pre>${body}</pre>
      <div style="color:var(--dim);font-size:11px">hash ${e.hash.slice(0,16)}… ← prev ${e.prev_hash.slice(0,16)}…</div>
    </div></div>`;
}

function esc(s) { return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
loadSessions();
setInterval(loadSessions, 5000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE


def main() -> None:
    global _store
    parser = argparse.ArgumentParser(description="flightrec replay UI")
    parser.add_argument("--root", default="./traces")
    parser.add_argument("--port", type=int, default=8377)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    _store = TraceStore(args.root)
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
