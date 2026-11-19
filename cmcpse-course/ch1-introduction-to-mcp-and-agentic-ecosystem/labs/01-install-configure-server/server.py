"""A pure-Python stdio MCP-style server, driven by a config file.

Not the official SDK. It speaks the same wire format (newline-delimited JSON-RPC 2.0
on stdin/stdout) and a small subset of MCP: initialize, notifications/initialized,
ping, tools/list, tools/call.

Run:  python server.py --config config.json

Standard library only, so it also works under ``python -I`` (isolated mode).
stdout is the protocol channel: NEVER print debug text there. Use stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SUPPORTED_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602
MAX_READ_BYTES = 10_000

TOOL_DEFS: dict[str, dict[str, Any]] = {
    "echo": {
        "description": "Return the given text unchanged.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                        "required": ["text"], "additionalProperties": False},
    },
    "add": {
        "description": "Add two numbers.",
        "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                        "required": ["a", "b"], "additionalProperties": False},
    },
    "list_files": {
        "description": "List file names in the configured root directory (not recursive).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "read_file": {
        "description": "Read a small text file that lives inside the configured root directory.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                        "required": ["path"], "additionalProperties": False},
    },
}


def load_config(path: Path) -> dict[str, Any]:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    unknown = [t for t in cfg.get("tools_enabled", []) if t not in TOOL_DEFS]
    if unknown:
        raise ValueError(f"unknown tools in config: {unknown}")
    cfg.setdefault("name", "configurable-server")
    cfg.setdefault("version", "0.1.0")
    cfg.setdefault("tools_enabled", [])
    # A relative root_dir is relative to the config file, not to the current directory.
    cfg["_root"] = (path.parent / cfg.get("root_dir", ".")).resolve()
    return cfg


def safe_path(root: Path, user_path: str) -> Path:
    """Resolve user_path and refuse anything that ends up outside root (.., absolute, symlinks)."""
    candidate = (root / user_path).resolve()
    if not candidate.is_relative_to(root):
        raise PermissionError("path is outside the root directory")
    return candidate


class ConfigServer:
    def __init__(self, config: dict[str, Any]) -> None:
        self.cfg = config
        self.root: Path = config["_root"]
        self.enabled = list(config["tools_enabled"])
        self.initialized = False

    # --- tool implementations (each returns text; raising = tool error) ---
    def _run_tool(self, name: str, args: dict[str, Any]) -> str:
        if name == "echo":
            return str(args["text"])
        if name == "add":
            return str(args["a"] + args["b"])
        if name == "list_files":
            return "\n".join(sorted(p.name for p in self.root.iterdir() if p.is_file()))
        if name == "read_file":
            target = safe_path(self.root, str(args["path"]))
            return target.read_bytes()[:MAX_READ_BYTES].decode("utf-8", errors="replace")
        raise KeyError(name)

    def _check_args(self, name: str, args: dict[str, Any]) -> str | None:
        """Tiny schema check: required, types, no extra keys. Returns an error text or None."""
        schema = TOOL_DEFS[name]["inputSchema"]
        for key in args:
            if key not in schema["properties"]:
                return f"unexpected argument: {key}"
        for key in schema.get("required", []):
            if key not in args:
                return f"missing argument: {key}"
        for key, value in args.items():
            kind = schema["properties"][key]["type"]
            ok = (isinstance(value, str) if kind == "string"
                  else isinstance(value, (int, float)) and not isinstance(value, bool))
            if not ok:
                return f"argument {key} must be a {kind}"
        return None

    # --- JSON-RPC layer ---
    def handle(self, msg: Any) -> dict[str, Any] | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return self._err(msg.get("id") if isinstance(msg, dict) else None, INVALID_REQUEST, "Invalid Request")
        method, params = msg["method"], msg.get("params") or {}
        if "id" not in msg:  # notification: never answer
            return None
        rid = msg["id"]
        if method == "initialize":
            wanted = params.get("protocolVersion")
            version = wanted if wanted in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
            self.initialized = True
            return self._ok(rid, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.cfg["name"], "version": self.cfg["version"]},
            })
        if method == "ping":
            return self._ok(rid, {})
        if not self.initialized:
            return self._err(rid, INVALID_REQUEST, "Server not initialized")
        if method == "tools/list":
            tools = [{"name": n, **TOOL_DEFS[n]} for n in self.enabled]
            return self._ok(rid, {"tools": tools})
        if method == "tools/call":
            name = params.get("name")
            if name not in self.enabled:  # disabled tools do not exist as far as clients can tell
                return self._err(rid, INVALID_PARAMS, f"Unknown tool: {name}")
            args = params.get("arguments") or {}
            problem = self._check_args(name, args)
            if problem:
                return self._ok(rid, self._tool_result(problem, True))
            try:
                return self._ok(rid, self._tool_result(self._run_tool(name, args), False))
            except (OSError, PermissionError) as exc:
                return self._ok(rid, self._tool_result(f"{type(exc).__name__}: {exc}", True))
        return self._err(rid, METHOD_NOT_FOUND, f"Method not found: {method}")

    @staticmethod
    def _tool_result(text: str, is_error: bool) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": text}], "isError": is_error}

    @staticmethod
    def _ok(rid: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def serve(server: ConfigServer, stdin=sys.stdin, stdout=sys.stdout) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            reply: dict[str, Any] | None = server._err(None, PARSE_ERROR, "Parse error")
        else:
            reply = server.handle(msg)
        if reply is not None:
            stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
            stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    cfg = load_config(args.config)
    print(f"[{cfg['name']}] started, tools={cfg['tools_enabled']}, root={cfg['_root']}", file=sys.stderr)
    serve(ConfigServer(cfg))


if __name__ == "__main__":
    main()
