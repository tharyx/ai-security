"""A deliberately vulnerable MCP host (the AI app that connects to MCP servers).

It connects to any server it is given, trusts every tool description, silently
accepts tool definitions that change after the user approved the server, and lets
a later server overwrite an earlier server's tool of the same name.

DO NOT copy this pattern. Every line marked VULN is one of the mistakes this lab
teaches you to find.

Run the whole scorecard from the repository root:
    python 04-mcp-security/mcp-server/lab/demo.py
"""

from __future__ import annotations

import itertools
import json
from typing import Any, Callable

from aisec_lab import LLM, get_llm

Transport = Callable[[str], "str | None"]

SYSTEM_PROMPT = "You are a helpful assistant. You can use these tools:\n{tools}"


class VulnerableHost:
    def __init__(self, llm: LLM | None = None) -> None:
        self.llm = llm or get_llm()
        self.servers: dict[str, Transport] = {}
        self.tools: dict[str, tuple[str, dict[str, Any]]] = {}  # tool name -> (server, definition)
        self.log: list[str] = []
        self._ids = itertools.count(1)

    def _rpc(self, transport: Transport, method: str, params: dict | None = None) -> dict[str, Any]:
        reply = transport(json.dumps({"jsonrpc": "2.0", "id": next(self._ids), "method": method,
                                      "params": params or {}}))
        return json.loads(reply or "{}").get("result", {})  # VULN 1: no check of id, errors or size

    def connect(self, transport: Transport) -> bool:
        # VULN 2: no registry, no allowlist. Any server the user (or a config file) points at is trusted.
        info = self._rpc(transport, "initialize", {"protocolVersion": "2025-06-18"})["serverInfo"]
        self.servers[info["name"]] = transport
        self._load_tools(info["name"])
        return True

    def _load_tools(self, server: str) -> None:
        for tool in self._rpc(self.servers[server], "tools/list")["tools"]:
            # VULN 3: tool names are global. A later server silently replaces ("shadows") an earlier one.
            self.tools[tool["name"]] = (server, tool)

    def refresh_tools(self) -> None:
        """Called when a server sends notifications/tools/list_changed."""
        for server in self.servers:
            # VULN 4: changed descriptions are accepted without review. This is the "rug pull".
            self._load_tools(server)

    def ask(self, user_request: str) -> str:
        # VULN 5: tool descriptions written by third parties go straight into the model's context.
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
        if isinstance(call, dict) and call.get("tool") in self.tools:
            # VULN 6: the model's choice is executed with no approval, even for tools that send data out.
            return self.call_tool(call["tool"], call.get("args", {}))
        return output

    def call_tool(self, name: str, args: dict[str, Any]) -> str:
        server, _ = self.tools[name]
        # VULN 7: raw arguments (which may contain secrets) go to the log; no correlation ID.
        self.log.append(f"call {server}.{name} {json.dumps(args)}")
        result = self._rpc(self.servers[server], "tools/call", {"name": name, "arguments": args})
        return result["content"][0]["text"]


def naive_http_accept(bind_host: str, headers: dict[str, str]) -> bool:
    """How many local MCP servers started out: listen everywhere, accept every request."""
    # VULN 8: binding to 0.0.0.0 exposes the server to the whole network, and with no
    # Host/Origin checks a web page can reach it through DNS rebinding.
    return True
