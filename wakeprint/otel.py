"""OpenTelemetry export — replay a wakeprint session as OTel spans.

Bridges the evidence store into existing observability stacks (Datadog,
Grafana, Jaeger, Honeycomb...) so teams can see agent sessions next to
the rest of their telemetry. The OTel copy is a *view*; the hash-chained
trace remains the evidence of record.

Requires the optional extra:  pip install "wakeprint[otel]"

    wakeprint otel SESSION_ID                          # console exporter
    wakeprint otel SESSION_ID --endpoint http://collector:4318/v1/traces
"""

from __future__ import annotations

from typing import Any

from .store import TraceStore

_PAIRS = {"tool_call": ("tool_result", "tool_error"), "llm_request": ("llm_response",)}


def _ns(ts: float) -> int:
    return int(ts * 1e9)


def _pair_events(events: list[dict[str, Any]]) -> list[tuple[dict, dict | None]]:
    """Pair start events with their completion (tool_call->tool_result, etc.)."""
    used: set[int] = set()
    pairs: list[tuple[dict, dict | None]] = []
    for i, e in enumerate(events):
        if i in used:
            continue
        end_types = _PAIRS.get(e["type"])
        if not end_types:
            if e["type"] not in {"tool_result", "tool_error", "llm_response"}:
                pairs.append((e, None))
            continue
        match = None
        e_rpc = e.get("payload", {}).get("rpc_id")
        e_tool = e.get("payload", {}).get("tool")
        for j in range(i + 1, len(events)):
            c = events[j]
            if j in used or c["type"] not in end_types:
                continue
            c_rpc = c.get("payload", {}).get("rpc_id")
            c_tool = c.get("payload", {}).get("tool")
            if e_rpc is not None and c_rpc is not None and e_rpc != c_rpc:
                continue
            if e_tool and c_tool and e_tool != c_tool:
                continue
            match = c
            used.add(j)
            break
        pairs.append((e, match))
    return pairs


def export_session(
    store: TraceStore,
    session_id: str,
    tracer_provider: Any = None,
    endpoint: str | None = None,
) -> int:
    """Export one session as OTel spans. Returns the number of spans emitted."""
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider

    events = list(store.read(session_id))
    if not events:
        raise ValueError(f"session {session_id} is empty or missing")
    head = events[0]

    if tracer_provider is None:
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

        tracer_provider = TracerProvider(
            resource=Resource.create({"service.name": "wakeprint"}))
        if endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            tracer_provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        else:
            tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    tracer = tracer_provider.get_tracer("wakeprint")
    count = 0

    root = tracer.start_span(
        f"agent.session {head.get('name', session_id)}",
        start_time=_ns(head["ts"]),
        attributes={"wakeprint.session_id": session_id},
    )
    ctx = trace.set_span_in_context(root)

    for start, end in _pair_events(events[1:]):
        p = start.get("payload", {})
        name = {
            "tool_call": f"tool {p.get('tool', '?')}",
            "llm_request": f"llm {p.get('provider', '?')}",
        }.get(start["type"], start["type"])
        attrs: dict[str, Any] = {"wakeprint.seq": start["seq"], "wakeprint.type": start["type"]}
        if p.get("tool"):
            attrs["wakeprint.tool"] = p["tool"]
        flags = (end or start).get("payload", {}).get("_flags") or p.get("_flags")
        if flags:
            attrs["wakeprint.flagged"] = True
            attrs["wakeprint.verdicts"] = ", ".join(sorted({f["label"] for f in flags}))
            attrs["wakeprint.risk"] = (end or start).get("payload", {}).get("_risk", p.get("_risk", 0))
        span = tracer.start_span(name, context=ctx, start_time=_ns(start["ts"]), attributes=attrs)
        if end and end["type"] in ("tool_error",):
            span.set_status(trace.status.Status(trace.status.StatusCode.ERROR))
        span.end(end_time=_ns((end or start)["ts"]))
        count += 1

    root.end(end_time=_ns(events[-1]["ts"]))
    count += 1
    if hasattr(tracer_provider, "force_flush"):
        tracer_provider.force_flush()
    return count
