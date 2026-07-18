"""Recorder SDK.

Usage:

    from flightrec import Recorder

    rec = Recorder(root="./traces")
    with rec.session("support-agent run") as s:
        client = s.wrap_openai(OpenAI())          # or s.wrap_anthropic(Anthropic())

        @s.record_tool
        def send_email(to: str, body: str): ...

        # use client / tools as normal — everything is traced

Every model request/response and tool call/result is appended to a
hash-chained trace, scanned for injection heuristics, and available for
replay in the web UI.
"""

from __future__ import annotations

import functools
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .scan import scan_payload, risk_score
from .store import TraceStore


def _safe(obj: Any, depth: int = 0) -> Any:
    """Best-effort conversion of SDK objects to JSON-serializable data."""
    if depth > 6:
        return str(obj)
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _safe(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_safe(v, depth + 1) for v in obj]
    if hasattr(obj, "model_dump"):  # pydantic (openai/anthropic SDKs)
        try:
            return _safe(obj.model_dump(), depth + 1)
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        try:
            return _safe(vars(obj), depth + 1)
        except Exception:
            pass
    return str(obj)


class Session:
    def __init__(self, store: TraceStore, session_id: str):
        self.store = store
        self.session_id = session_id

    # -- generic event ----------------------------------------------------

    def log(self, event_type: str, **payload: Any) -> None:
        payload = _safe(payload)
        findings = scan_payload(payload)
        if findings:
            payload["_flags"] = findings
            payload["_risk"] = risk_score(findings)
        self.store.append(self.session_id, event_type, payload)

    # -- tool recording ---------------------------------------------------

    def record_tool(self, fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            self.log("tool_call", tool=fn.__name__, args=_safe(list(args)), kwargs=_safe(kwargs))
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                self.log("tool_error", tool=fn.__name__, error=str(e), trace=traceback.format_exc()[-2000:])
                raise
            self.log("tool_result", tool=fn.__name__, result=_safe(result))
            return result

        return wrapper

    # -- LLM client wrappers -----------------------------------------------

    def wrap_openai(self, client: Any) -> Any:
        return _OpenAIProxy(client, self)

    def wrap_anthropic(self, client: Any) -> Any:
        return _AnthropicProxy(client, self)


class _RecordedCall:
    """Wraps a `.create(...)` style method, logging request and response."""

    def __init__(self, inner: Callable, session: Session, provider: str):
        self._inner = inner
        self._session = session
        self._provider = provider

    def __call__(self, **kwargs: Any) -> Any:
        self._session.log("llm_request", provider=self._provider, request=_safe(kwargs))
        response = self._inner(**kwargs)
        self._session.log("llm_response", provider=self._provider, response=_safe(response))
        return response


class _AttrProxy:
    """Generic attribute-path proxy that intercepts `create` methods."""

    _intercept = ("create",)

    def __init__(self, target: Any, session: Session, provider: str):
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_provider", provider)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(object.__getattribute__(self, "_target"), name)
        session = object.__getattribute__(self, "_session")
        provider = object.__getattribute__(self, "_provider")
        if name in self._intercept and callable(attr):
            return _RecordedCall(attr, session, provider)
        if callable(attr) and not hasattr(attr, "__self__"):
            return attr
        if not isinstance(attr, (bool, int, float, str, bytes, type(None))) and not callable(attr):
            return _AttrProxy(attr, session, provider)
        return attr


class _OpenAIProxy(_AttrProxy):
    def __init__(self, client: Any, session: Session):
        super().__init__(client, session, "openai")


class _AnthropicProxy(_AttrProxy):
    def __init__(self, client: Any, session: Session):
        super().__init__(client, session, "anthropic")


class Recorder:
    def __init__(self, root: str | Path = "./traces"):
        self.store = TraceStore(root)

    @contextmanager
    def session(self, name: str, metadata: dict[str, Any] | None = None) -> Iterator[Session]:
        session_id = self.store.create_session(name, metadata)
        s = Session(self.store, session_id)
        try:
            yield s
            s.log("session_end", status="ok")
        except Exception as e:
            s.log("session_end", status="error", error=str(e))
            raise
