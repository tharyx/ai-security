"""Tiny MCP-style JSON-RPC 2.0 server plus a gullible 'fresh content' model.

This file is copied into every lab of the chapter so that each lab is self-contained.
It is NOT the official MCP SDK: it copies only the *shape* of the protocol
(initialize, tools/list, tools/call, resources/*, prompts/*) so trust decisions are visible.

A transport is a function ``(raw_message: str, token: str | None) -> str | None``.
``Server.handle`` is one. In real MCP the same bytes travel over stdio or Streamable HTTP.
Everything is harmless: secrets are canaries, domains end in ``.example``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from aisec_lab import MockLLM
from aisec_lab.llm import TOOL_RE

PROTOCOL_VERSION = "2025-06-18"
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603
UNAUTHORIZED = -32001  # an HTTP 401 on a real Streamable HTTP endpoint


class ToolError(Exception):
    """A deliberate, safe error message for the caller (for example 'forbidden')."""


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[..., str]

    def definition(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema}


def schema(required: tuple[str, ...] = (), strict: bool = True, **props: dict[str, Any]) -> dict[str, Any]:
    d: dict[str, Any] = {"type": "object", "properties": props, "required": list(required or props)}
    if strict:
        d["additionalProperties"] = False
    return d


class Server:
    """A minimal JSON-RPC 2.0 server that speaks a small subset of MCP."""

    def __init__(self, name: str, version: str, tools: list[Tool] | None = None, *,
                 resources: dict[str, str] | None = None, prompts: dict[str, str] | None = None,
                 token: str | None = None, verbose_errors: bool = False, debug_info: str = "") -> None:
        self.name, self.version = name, version
        self.tools = {t.name: t for t in (tools or [])}
        self.resources = resources or {}   # uri -> text
        self.prompts = prompts or {}       # name -> template text
        self.token = token                 # None means: no authentication at all
        self.verbose_errors = verbose_errors
        self.debug_info = debug_info       # what a verbose error leaks (a canary in the labs)
        self.calls: list[dict[str, Any]] = []

    def handle(self, raw: str, token: str | None = None) -> str | None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return self._error(None, PARSE_ERROR, "Parse error")
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return self._error(None, INVALID_REQUEST, "Invalid Request")
        if self.token is not None and token != self.token:
            return self._error(msg.get("id"), UNAUTHORIZED, "Unauthorized")
        if "id" not in msg:
            return None  # notification
        rid, method, params = msg["id"], msg["method"], msg.get("params") or {}
        if method == "initialize":
            return self._result(rid, {"protocolVersion": PROTOCOL_VERSION,
                                      "capabilities": {"tools": {"listChanged": True}, "resources": {}, "prompts": {}},
                                      "serverInfo": {"name": self.name, "version": self.version}})
        if method == "tools/list":
            return self._result(rid, {"tools": [t.definition() for t in self.tools.values()]})
        if method == "resources/list":
            return self._result(rid, {"resources": [{"uri": u, "name": u.rsplit("/", 1)[-1]} for u in self.resources]})
        if method == "resources/read":
            uri = params.get("uri", "")
            if uri not in self.resources:
                return self._error(rid, INVALID_PARAMS, "Unknown resource")
            return self._result(rid, {"contents": [{"uri": uri, "text": self.resources[uri]}]})
        if method == "prompts/list":
            return self._result(rid, {"prompts": [{"name": n} for n in self.prompts]})
        if method == "prompts/get":
            n = params.get("name", "")
            if n not in self.prompts:
                return self._error(rid, INVALID_PARAMS, "Unknown prompt")
            return self._result(rid, {"messages": [{"role": "user", "content": {"type": "text", "text": self.prompts[n]}}]})
        if method == "tools/call":
            return self._call(rid, params)
        return self._error(rid, METHOD_NOT_FOUND, f"Method not found: {method}")

    def _call(self, rid: Any, params: dict[str, Any]) -> str:
        tool = self.tools.get(params.get("name", ""))
        if tool is None:
            return self._error(rid, INVALID_PARAMS, f"Unknown tool: {params.get('name')}")
        args = params.get("arguments") or {}
        try:
            text = tool.handler(**args)
        except ToolError as exc:
            return self._error(rid, -32000, str(exc))
        except TypeError as exc:
            return self._error(rid, INVALID_PARAMS, f"Invalid arguments: {exc}" if self.verbose_errors else "Invalid arguments")
        except Exception as exc:  # noqa: BLE001 - a lab: we want to show what leaks
            if self.verbose_errors:
                return self._error(rid, INTERNAL_ERROR, f"{type(exc).__name__}: {exc} | {self.debug_info}")
            return self._error(rid, INTERNAL_ERROR, "Internal error")
        self.calls.append({"tool": tool.name, "arguments": args})
        return self._result(rid, {"content": [{"type": "text", "text": str(text)}], "isError": False})

    @staticmethod
    def _result(rid: Any, result: dict[str, Any]) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": result})

    @staticmethod
    def _error(rid: Any, code: int, message: str) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})


def request(transport: Callable[..., str | None], method: str, params: dict[str, Any] | None = None,
            token: str | None = None, rid: int = 1) -> dict[str, Any]:
    """Send one JSON-RPC request through a transport and return the parsed reply."""
    raw = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
    reply = transport(raw, token)
    return json.loads(reply) if reply else {}


def call_tool(transport: Callable[..., str | None], name: str, arguments: dict[str, Any], token: str | None = None) -> str:
    """tools/call helper: returns the text, or raises RuntimeError with the server's error message."""
    r = request(transport, "tools/call", {"name": name, "arguments": arguments}, token)
    if "error" in r:
        raise RuntimeError(r["error"]["message"])
    return r["result"]["content"][0]["text"]


def parse_call(model_output: str) -> dict[str, Any] | None:
    """MockLLM returns a tool call as JSON ``{"tool": ..., "args": ...}``. Return it, or None for plain text."""
    try:
        d = json.loads(model_output)
    except json.JSONDecodeError:
        return None
    return d if isinstance(d, dict) and "tool" in d else None


class FreshestLLM(MockLLM):
    """A gullible model that obeys a ``CALL_TOOL`` directive in the freshest message and ignores older ones.

    Real models weigh recent context heavily, so a directive hidden in the latest tool result
    often wins. With no directive in the latest message it just answers.
    """

    def complete(self, messages):
        system = [m for m in messages if m["role"] == "system"]
        last = messages[-1]
        if TOOL_RE.search(last["content"]):
            return super().complete(system + [{"role": "user", "content": last["content"]}])
        self.calls.append([dict(m) for m in messages])
        return "Done."
