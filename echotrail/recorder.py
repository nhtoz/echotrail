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
import sys
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
        v = d.get("delta")  # anthropic: delta.text
        if isinstance(v, dict) and isinstance(v.get("text"), str):
            return v["text"]
        # content_block_start may carry initial text; content_block_stop (from
        # messages.stream()) repeats the whole block, so it must not count
        v = d.get("content_block")
        if d.get("type", "content_block_start") == "content_block_start" \
                and isinstance(v, dict) and isinstance(v.get("text"), str):
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


class _RecordingMessageStream:
    """Wraps the stream object a `.stream(...)` context manager yields
    (Anthropic `messages.stream()`, OpenAI `chat.completions.stream()`).

    Events and `text_stream` pass through untouched; one llm_response is
    logged when the context exits, preferring the SDK's own accumulated
    snapshot over our reassembled text.
    """

    _SNAPSHOTS = ("current_message_snapshot", "current_completion_snapshot")

    def __init__(self, stream: Any, session: Session, provider: str):
        self._stream, self._session, self._provider = stream, session, provider
        self._text: list[str] = []
        self._chunks = 0
        self._done = False

    def __iter__(self):
        for event in self._stream:
            self._chunks += 1
            self._text.append(_delta_text(event))
            yield event

    async def __aiter__(self):
        async for event in self._stream:
            self._chunks += 1
            self._text.append(_delta_text(event))
            yield event

    @property
    def text_stream(self) -> Any:
        inner = self._stream.text_stream
        if hasattr(inner, "__aiter__"):
            async def agen():
                async for text in inner:
                    self._text.append(text)
                    yield text
            return agen()

        def gen():
            for text in inner:
                self._text.append(text)
                yield text
        return gen()

    def _finish(self, error: BaseException | None = None) -> None:
        if self._done:
            return
        self._done = True
        response: Any = None
        for name in self._SNAPSHOTS:
            try:
                snap = getattr(self._stream, name)
            except Exception:
                continue
            if snap is not None:
                response = _safe(snap)
                break
        if response is None:
            response = {"content": "".join(self._text)}
        extra = {"error": str(error)} if error else {}
        self._session.log("llm_response", provider=self._provider, streamed=True,
                          chunk_count=self._chunks, response=response, **extra)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class _RecordingStreamManager:
    """Wraps the context manager returned by `.stream(...)` (sync or async)."""

    def __init__(self, manager: Any, session: Session, provider: str):
        self._manager, self._session, self._provider = manager, session, provider
        self._rs: _RecordingMessageStream | None = None

    def __enter__(self) -> _RecordingMessageStream:
        self._rs = _RecordingMessageStream(self._manager.__enter__(), self._session, self._provider)
        return self._rs

    def _finish(self, error: BaseException | None) -> None:
        if self._rs is None:
            return
        try:
            self._rs._finish(error)
        except Exception as e:  # recording must never break the agent's stream
            print(f"echotrail: record error: {e}", file=sys.stderr)

    def __exit__(self, *exc: Any) -> Any:
        self._finish(exc[1])
        return self._manager.__exit__(*exc)

    async def __aenter__(self) -> _RecordingMessageStream:
        self._rs = _RecordingMessageStream(await self._manager.__aenter__(), self._session, self._provider)
        return self._rs

    async def __aexit__(self, *exc: Any) -> Any:
        self._finish(exc[1])
        return await self._manager.__aexit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._manager, name)


class _RecordedStreamCall:
    """Wraps a `.stream(...)` method: logs the request, records the stream."""

    def __init__(self, inner: Callable, session: Session, provider: str):
        self._inner, self._session, self._provider = inner, session, provider

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._session.log("llm_request", provider=self._provider, streamed=True, request=_safe(kwargs))
        return _RecordingStreamManager(self._inner(*args, **kwargs), self._session, self._provider)


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
    """Generic attribute-path proxy that intercepts `create` and `stream` methods."""

    _intercept = {"create": _RecordedCall, "stream": _RecordedStreamCall}

    def __init__(self, target: Any, session: Session, provider: str):
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_provider", provider)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(object.__getattribute__(self, "_target"), name)
        session = object.__getattribute__(self, "_session")
        provider = object.__getattribute__(self, "_provider")
        if name in self._intercept and callable(attr):
            return self._intercept[name](attr, session, provider)
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
