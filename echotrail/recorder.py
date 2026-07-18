"""Recorder SDK.

Usage:

    from echotrail import Recorder

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
import inspect
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

    # -- configuration capture --------------------------------------------

    def snapshot_config(
        self,
        system_prompt: str | None = None,
        model: str | None = None,
        tools: list[str] | None = None,
        **extra: Any,
    ) -> None:
        """Record the agent's configuration at this point in the session.

        The most frequently missing evidence in agent incident forensics
        is the exact system prompt / model version in force at incident
        time. Capture it inside the hash chain so it can't be disputed.
        """
        self.log(
            "config_snapshot",
            system_prompt=system_prompt,
            model=model,
            tools=tools or [],
            **extra,
        )

    # -- tool recording ---------------------------------------------------

    def record_tool(self, fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                self.log("tool_call", tool=fn.__name__, args=_safe(list(args)), kwargs=_safe(kwargs))
                try:
                    result = await fn(*args, **kwargs)
                except Exception as e:
                    self.log("tool_error", tool=fn.__name__, error=str(e), trace=traceback.format_exc()[-2000:])
                    raise
                self.log("tool_result", tool=fn.__name__, result=_safe(result))
                return result

            return async_wrapper

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


def _delta_text(chunk: Any) -> str:
    """Best-effort extraction of streamed text deltas (OpenAI/Anthropic shapes)."""
    d = _safe(chunk)
    if isinstance(d, dict):
        try:  # openai: choices[0].delta.content
            c = d.get("choices", [{}])[0].get("delta", {}).get("content")
            if isinstance(c, str):
                return c
        except Exception:
            pass
        for key in ("delta", "content_block"):  # anthropic: delta.text
            v = d.get(key)
            if isinstance(v, dict) and isinstance(v.get("text"), str):
                return v["text"]
    return ""


class _RecordingStream:
    """Wraps a sync stream: relays chunks, logs one llm_response at the end."""

    def __init__(self, stream: Any, session: Session, provider: str):
        self._stream, self._session, self._provider = stream, session, provider
        self._text, self._chunks = [], 0

    def __iter__(self):
        try:
            for chunk in self._stream:
                self._chunks += 1
                self._text.append(_delta_text(chunk))
                yield chunk
        finally:
            self._session.log("llm_response", provider=self._provider, streamed=True,
                              chunk_count=self._chunks, response={"content": "".join(self._text)})

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class _AsyncRecordingStream:
    """Async variant of _RecordingStream."""

    def __init__(self, stream: Any, session: Session, provider: str):
        self._stream, self._session, self._provider = stream, session, provider
        self._text, self._chunks = [], 0

    async def __aiter__(self):
        try:
            async for chunk in self._stream:
                self._chunks += 1
                self._text.append(_delta_text(chunk))
                yield chunk
        finally:
            self._session.log("llm_response", provider=self._provider, streamed=True,
                              chunk_count=self._chunks, response={"content": "".join(self._text)})

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class _RecordedCall:
    """Wraps a `.create(...)` style method (sync or async, streaming or not)."""

    def __init__(self, inner: Callable, session: Session, provider: str):
        self._inner = inner
        self._session = session
        self._provider = provider

    def __call__(self, **kwargs: Any) -> Any:
        self._session.log("llm_request", provider=self._provider, request=_safe(kwargs))
        result = self._inner(**kwargs)
        if inspect.isawaitable(result):
            return self._finish_async(result)
        return self._finish(result)

    def _finish(self, response: Any) -> Any:
        if hasattr(response, "__aiter__"):
            return _AsyncRecordingStream(response, self._session, self._provider)
        if hasattr(response, "__iter__") and not hasattr(response, "model_dump") \
                and not isinstance(response, (dict, list, str, bytes)):
            return _RecordingStream(response, self._session, self._provider)
        self._session.log("llm_response", provider=self._provider, response=_safe(response))
        return response

    async def _finish_async(self, coro: Any) -> Any:
        return self._finish(await coro)


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
    def session(
        self,
        name: str,
        metadata: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
    ) -> Iterator[Session]:
        """Open a recorded session. Pass `config` (system_prompt, model,
        tools, ...) to snapshot agent configuration as the first chained event."""
        session_id = self.store.create_session(name, metadata)
        s = Session(self.store, session_id)
        if config:
            s.snapshot_config(**config)
        try:
            yield s
            s.log("session_end", status="ok")
        except Exception as e:
            s.log("session_end", status="error", error=str(e))
            raise
