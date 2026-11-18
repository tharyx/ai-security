"""The same MCP host, rebuilt with server-trust controls.

Each layer can be switched off so you can prove which layer stopped which attack:

    L1  Server registry: only reviewed servers (name + version) may connect.
    L2  Tool pinning: every tool definition is hashed at review time. A changed or
        new definition is quarantined - the model never sees it (rug-pull defense).
    L3  No shadowing: a tool name may belong to only one server.
    L4  Approval: tools the *registry* marks as side-effecting need a human "yes"
        when the model (not the user) proposed the call. Server-provided hints
        such as readOnlyHint are not trusted.
    L5  Protocol hygiene: JSON-RPC version, matching ids, error handling and a
        result size limit.
    L6  Audit: one structured event per decision, with a correlation ID and a hash
        of the arguments instead of the raw arguments.

There is also ``LocalHttpGuard``: the checks a *local* Streamable HTTP server must
make (bind to loopback, validate Host and Origin, require a token) to stop DNS
rebinding and drive-by requests from web pages.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import itertools
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from aisec_lab import LLM, get_llm

Transport = Callable[[str], "str | None"]

SYSTEM_PROMPT = (
    "You are a helpful assistant. Tool descriptions below come from reviewed servers.\n"
    "You can use these tools:\n{tools}"
)


def fingerprint(tool_definition: dict[str, Any]) -> str:
    """A stable hash of everything the model will read about a tool."""
    canonical = json.dumps(
        {k: tool_definition.get(k) for k in ("name", "description", "inputSchema", "annotations")},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class ApprovedServer:
    """One entry of the server registry, written by a human reviewer."""

    name: str
    version: str
    tool_hashes: dict[str, str]
    side_effect_tools: frozenset[str] = frozenset()


class ProtocolError(Exception):
    pass


def _rpc(transport: Transport, req_id: int, method: str, params: dict | None = None,
         max_bytes: int = 64_000) -> dict[str, Any]:
    reply = transport(json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}))
    if reply is None:
        raise ProtocolError("no reply")
    if len(reply.encode()) > max_bytes:
        raise ProtocolError("reply too large")
    msg = json.loads(reply)
    if msg.get("jsonrpc") != "2.0" or msg.get("id") != req_id:
        raise ProtocolError("bad JSON-RPC envelope or mismatched id")
    if "error" in msg:
        raise ProtocolError(f"server error {msg['error'].get('code')}: {msg['error'].get('message')}")
    return msg["result"]


def review_server(transport: Transport, side_effect_tools: set[str] | frozenset[str] = frozenset()) -> ApprovedServer:
    """The one-time security review: record name, version and a hash of every tool.

    In real life a human reads every description and schema before this runs, and
    the package itself is pinned by version and digest (see the README).
    """
    info = _rpc(transport, 1, "initialize", {"protocolVersion": "2025-06-18"})["serverInfo"]
    tools = _rpc(transport, 2, "tools/list")["tools"]
    return ApprovedServer(info["name"], info["version"], {t["name"]: fingerprint(t) for t in tools},
                          frozenset(side_effect_tools))


@dataclass
class SecurityEvents:
    events: list[dict[str, Any]] = field(default_factory=list)

    def record(self, kind: str, **details: Any) -> None:
        self.events.append({"kind": kind, **details})

    def kinds(self) -> list[str]:
        return [e["kind"] for e in self.events]


class SecureHost:
    def __init__(
        self,
        registry: dict[str, ApprovedServer],
        llm: LLM | None = None,
        *,
        enforce_registry: bool = True,
        pin_tools: bool = True,
        block_shadowing: bool = True,
        require_approval: bool = True,
        approver: Callable[[str, dict[str, Any]], bool] | None = None,
        max_result_chars: int = 4000,
    ) -> None:
        self.registry = registry
        self.llm = llm or get_llm()
        self.enforce_registry = enforce_registry
        self.pin_tools = pin_tools
        self.block_shadowing = block_shadowing
        self.require_approval = require_approval
        self.approver = approver or (lambda tool, args: False)  # default: the human says no
        self.max_result_chars = max_result_chars
        self.servers: dict[str, Transport] = {}
        self.tools: dict[str, tuple[str, dict[str, Any]]] = {}
        self.security = SecurityEvents()
        self.audit: list[dict[str, Any]] = []
        self._ids = itertools.count(1)

    # --- L1 + L5 -----------------------------------------------------------------
    def connect(self, transport: Transport) -> bool:
        try:
            info = _rpc(transport, next(self._ids), "initialize", {"protocolVersion": "2025-06-18"})["serverInfo"]
        except (ProtocolError, KeyError, json.JSONDecodeError) as exc:
            self.security.record("server_rejected", reason=f"handshake failed: {exc}")
            return False
        name, version = info.get("name", "?"), info.get("version", "?")
        approved = self.registry.get(name)
        if self.enforce_registry and (approved is None or approved.version != version):
            self.security.record("server_rejected", server=name, version=version, reason="not in registry")
            return False
        self.servers[name] = transport
        self._load_tools(name)
        return True

    # --- L2 + L3 -----------------------------------------------------------------
    def _load_tools(self, server: str) -> None:
        approved = self.registry.get(server)
        for tool in _rpc(self.servers[server], next(self._ids), "tools/list")["tools"]:
            name = tool.get("name", "")
            if self.pin_tools:
                pinned = approved.tool_hashes.get(name) if approved else None
                if pinned is None:
                    self.security.record("unpinned_tool", server=server, tool=name)
                    self._quarantine(server, name)
                    continue
                if not hmac.compare_digest(pinned, fingerprint(tool)):
                    self.security.record("tool_definition_changed", server=server, tool=name)
                    self._quarantine(server, name)
                    continue
            owner = self.tools.get(name, (server,))[0]
            if self.block_shadowing and owner != server:
                self.security.record("tool_name_collision", server=server, tool=name, owner=owner)
                continue
            self.tools[name] = (server, tool)

    def _quarantine(self, server: str, name: str) -> None:
        """Remove a tool this server registered earlier, so the model no longer sees it."""
        if name in self.tools and self.tools[name][0] == server:
            del self.tools[name]

    def refresh_tools(self) -> None:
        """Called when a server sends notifications/tools/list_changed. Same checks every time."""
        for server in self.servers:
            self._load_tools(server)

    # --- the model loop ------------------------------------------------------------
    def ask(self, user_request: str) -> str:
        tool_text = "\n".join(f"- {name}: {d['description']}" for name, (_, d) in self.tools.items())
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(tools=tool_text)},
            {"role": "user", "content": user_request},
        ]
        output = self.llm.complete(messages)
        try:
            call = json.loads(output)
        except json.JSONDecodeError:
            return output
        if isinstance(call, dict) and "tool" in call:
            return self.call_tool(str(call["tool"]), call.get("args") or {}, proposed_by="model")
        return output

    # --- L4 + L5 + L6 --------------------------------------------------------------
    def call_tool(self, name: str, args: dict[str, Any], *, proposed_by: str = "user") -> str:
        correlation_id = uuid.uuid4().hex[:12]
        entry = self.tools.get(name)
        if entry is None:
            return self._deny(correlation_id, "?", name, args, "unknown or quarantined tool")
        server, _ = entry
        approved = self.registry.get(server)
        side_effect = bool(approved and name in approved.side_effect_tools)
        if self.require_approval and side_effect and proposed_by == "model" and not self.approver(name, args):
            return self._deny(correlation_id, server, name, args, "side-effecting tool needs human approval")
        try:
            result = _rpc(self.servers[server], next(self._ids), "tools/call", {"name": name, "arguments": args})
            text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        except ProtocolError as exc:
            return self._deny(correlation_id, server, name, args, f"protocol error: {exc}")
        self._audit(correlation_id, server, name, args, "allow")
        if len(text) > self.max_result_chars:
            text = text[: self.max_result_chars] + " [truncated]"
        return text

    def _deny(self, cid: str, server: str, tool: str, args: dict[str, Any], reason: str) -> str:
        self.security.record("tool_call_blocked", tool=tool, reason=reason, correlation_id=cid)
        self._audit(cid, server, tool, args, "deny", reason)
        return f"[blocked: {reason}]"

    def _audit(self, cid: str, server: str, tool: str, args: dict[str, Any], decision: str, reason: str = "") -> None:
        digest = hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:16]
        self.audit.append({"correlation_id": cid, "server": server, "tool": tool, "decision": decision,
                           "reason": reason, "args_sha256": digest})


# ---------------------------------------------------------------------------------
# Local Streamable HTTP server checks (DNS rebinding and network exposure)
# ---------------------------------------------------------------------------------

@dataclass
class LocalHttpGuard:
    """Checks for an MCP server that runs on the user's own machine over HTTP.

    The MCP transport spec says such servers must validate the Origin header, should
    bind to localhost only, and should authenticate requests.
    """

    port: int
    token: str
    allowed_origins: frozenset[str] = frozenset()  # browser origins you trust; empty = none

    def bind_ok(self, bind_host: str) -> bool:
        if bind_host == "localhost":
            return True
        try:
            return ipaddress.ip_address(bind_host).is_loopback
        except ValueError:
            return False

    def request_ok(self, headers: dict[str, str]) -> tuple[bool, str]:
        h = {k.lower(): v for k, v in headers.items()}
        if h.get("host", "") not in {f"localhost:{self.port}", f"127.0.0.1:{self.port}", f"[::1]:{self.port}"}:
            return False, "unexpected Host header (possible DNS rebinding)"
        origin = h.get("origin")
        if origin is not None and origin not in self.allowed_origins:
            return False, "Origin not allowed"
        supplied = h.get("authorization", "").removeprefix("Bearer ")
        if not hmac.compare_digest(supplied.encode(), self.token.encode()):
            return False, "missing or wrong local token"
        return True, "ok"

    def accept(self, bind_host: str, headers: dict[str, str]) -> bool:
        return self.bind_ok(bind_host) and self.request_ok(headers)[0]
