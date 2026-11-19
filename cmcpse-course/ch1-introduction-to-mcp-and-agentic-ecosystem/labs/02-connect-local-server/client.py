"""A minimal MCP-style stdio client: spawn a server, handshake, negotiate, list and call tools.

Standard library only. The client is the part of the HOST that owns one server connection
(one client per server). It:

1. starts the server as a child process (stdio transport),
2. sends ``initialize`` with its protocol version and capabilities,
3. checks the server's answer (version, capabilities) and sends ``notifications/initialized``,
4. only then uses features the server said it has.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
from typing import Any

CLIENT_VERSION = "2025-06-18"  # the revision this client was written against


class MCPError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code, self.message = code, message


class MCPClient:
    def __init__(self, command: list[str], timeout: float = 10.0, capabilities: dict | None = None) -> None:
        self.timeout = timeout
        self.client_capabilities = capabilities or {}
        self.server_info: dict[str, Any] = {}
        self.server_capabilities: dict[str, Any] = {}
        self.protocol_version: str | None = None
        self._next_id = 0
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        threading.Thread(target=self._read_loop, daemon=True).start()

    # --- transport: newline-delimited JSON on stdin/stdout ---
    def _read_loop(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            self._lines.put(line)
        self._lines.put(None)  # EOF: the server exited

    def _send(self, msg: dict[str, Any]) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
        self._proc.stdin.flush()

    # --- JSON-RPC layer ---
    def notify(self, method: str, params: dict | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def request(self, method: str, params: dict | None = None) -> dict[str, Any]:
        self._next_id += 1
        rid = self._next_id
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        while True:
            try:
                line = self._lines.get(timeout=self.timeout)
            except queue.Empty:
                raise TimeoutError(f"no reply to {method} within {self.timeout}s") from None
            if line is None:
                raise ConnectionError("server closed the connection")
            reply = json.loads(line)
            if "method" in reply:  # a server-to-client request or notification
                if "id" in reply:  # we advertised no such feature, so refuse politely
                    self._send({"jsonrpc": "2.0", "id": reply["id"],
                                "error": {"code": -32601, "message": "Method not found"}})
                continue
            if reply.get("id") != rid:
                continue
            if "error" in reply:
                raise MCPError(reply["error"]["code"], reply["error"]["message"])
            return reply["result"]

    # --- MCP lifecycle ---
    def initialize(self, name: str = "lab-client", version: str = "0.1.0") -> dict[str, Any]:
        result = self.request("initialize", {
            "protocolVersion": CLIENT_VERSION,
            "capabilities": self.client_capabilities,
            "clientInfo": {"name": name, "version": version},
        })
        self.protocol_version = result["protocolVersion"]
        if self.protocol_version != CLIENT_VERSION:
            # The server picked another version. A real client disconnects if it cannot speak it.
            self.close()
            raise ConnectionError(f"server wants protocol {self.protocol_version}, client speaks {CLIENT_VERSION}")
        self.server_capabilities = result.get("capabilities", {})
        self.server_info = result.get("serverInfo", {})
        self.notify("notifications/initialized")
        return result

    def has_capability(self, name: str) -> bool:
        return name in self.server_capabilities

    def list_tools(self) -> list[dict[str, Any]]:
        if not self.has_capability("tools"):
            raise RuntimeError("server did not advertise the tools capability")
        return self.request("tools/list")["tools"]

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.has_capability("tools"):
            raise RuntimeError("server did not advertise the tools capability")
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self) -> None:
        if self._proc.stdin and not self._proc.stdin.closed:
            self._proc.stdin.close()  # for stdio, closing stdin is the polite shutdown
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.terminate()

    def __enter__(self) -> "MCPClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def result_text(result: dict[str, Any]) -> str:
    return "".join(part.get("text", "") for part in result.get("content", []))
