"""MCP recording proxy — zero-code capture for any MCP-based agent.

Sits between an MCP client (Claude Desktop, Claude Code, any agent
framework) and an MCP server over stdio, relaying JSON-RPC messages
untouched while recording them into a tamper-evident wakeprint trace.

The agent needs NO code changes. In the client's MCP config, wrap the
real server command:

    { "command": "wakeprint",
      "args": ["mcp-proxy", "--root", "/var/wakeprint/traces",
               "--name", "github-mcp", "--",
               "npx", "-y", "@modelcontextprotocol/server-github"] }

Every tools/call becomes a `tool_call` event (with arguments), every
response a `tool_result` — both scanned by the injection heuristics, so
a poisoned tool result is flagged in the trace exactly like SDK capture.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any, BinaryIO

from .recorder import Recorder, Session


def _parse(line: bytes) -> dict[str, Any] | None:
    try:
        msg = json.loads(line.decode("utf-8"))
        return msg if isinstance(msg, dict) else None
    except Exception:
        return None


class MCPProxy:
    def __init__(self, root: str, name: str, command: list[str]):
        self.root = root
        self.name = name
        self.command = command
        self._pending: dict[Any, dict[str, Any]] = {}
        self._lock = threading.Lock()

    # -- message handling -------------------------------------------------

    def _log_client_msg(self, s: Session, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        if method == "tools/call":
            params = msg.get("params", {})
            with self._lock:
                self._pending[msg.get("id")] = {"tool": params.get("name")}
            s.log("tool_call", tool=params.get("name"),
                  kwargs=params.get("arguments", {}), rpc_id=msg.get("id"))
        elif method:
            if msg.get("id") is not None:
                with self._lock:
                    self._pending[msg.get("id")] = {"method": method}
            s.log("mcp_request", method=method, params=msg.get("params"), rpc_id=msg.get("id"))

    def _log_server_msg(self, s: Session, msg: dict[str, Any]) -> None:
        if msg.get("method"):  # server-initiated notification/request
            s.log("mcp_notification", method=msg.get("method"), params=msg.get("params"))
            return
        rpc_id = msg.get("id")
        with self._lock:
            ctx = self._pending.pop(rpc_id, {})
        if "error" in msg:
            s.log("tool_error" if ctx.get("tool") else "mcp_error",
                  tool=ctx.get("tool"), method=ctx.get("method"),
                  error=msg["error"], rpc_id=rpc_id)
        elif ctx.get("tool"):
            s.log("tool_result", tool=ctx["tool"], result=msg.get("result"), rpc_id=rpc_id)
        else:
            s.log("mcp_response", method=ctx.get("method"), result=msg.get("result"), rpc_id=rpc_id)

    # -- relay loops -------------------------------------------------------

    def _relay(self, src: BinaryIO, dst: BinaryIO, s: Session, direction: str) -> None:
        try:
            for line in iter(src.readline, b""):
                msg = _parse(line)
                if msg is not None:
                    try:
                        if direction == "client->server":
                            self._log_client_msg(s, msg)
                        else:
                            self._log_server_msg(s, msg)
                    except Exception as e:  # recording must never break the agent
                        print(f"wakeprint: record error: {e}", file=sys.stderr)
                dst.write(line)
                dst.flush()
        except (BrokenPipeError, ValueError, OSError):
            pass
        finally:
            if direction == "client->server":
                try:
                    dst.close()  # client hung up -> let the server exit
                except Exception:
                    pass

    def run(self) -> int:
        child = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
        )
        rec = Recorder(root=self.root)
        with rec.session(self.name, metadata={"mode": "mcp-proxy", "command": self.command}) as s:
            t_up = threading.Thread(
                target=self._relay, args=(sys.stdin.buffer, child.stdin, s, "client->server"), daemon=True)
            t_down = threading.Thread(
                target=self._relay, args=(child.stdout, sys.stdout.buffer, s, "server->client"), daemon=True)
            t_up.start()
            t_down.start()
            code = child.wait()
            t_down.join(timeout=2)
            s.log("mcp_proxy_exit", exit_code=code)
        return code


def main(root: str, name: str | None, command: list[str]) -> int:
    if not command:
        print("usage: wakeprint mcp-proxy [--name NAME] -- <server command...>", file=sys.stderr)
        return 2
    return MCPProxy(root, name or f"mcp:{command[0]}", command).run()
