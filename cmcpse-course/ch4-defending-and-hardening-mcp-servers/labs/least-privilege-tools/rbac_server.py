"""A running, in-process MCP-style server with role-based access control for tools AND resources.

The policy (policy.yaml) is enforced in TWO places:
    * tools/list and resources/list  -> FILTER: the caller only sees what it may use (less to attack, less to leak)
    * tools/call and resources/read  -> ENFORCE: the real check. Filtering alone is not security: a client can
                                        still send a call for a tool it never saw listed.
Both use the same functions, allowed_tool() and allowed_resource(), so they cannot drift apart.

The role comes from the session (set by authentication, see defend-oauth-scopes), never from tool arguments or
model output. Messages are JSON-RPC 2.0 dictionaries (the style of 04-mcp-security/mcp-server).
"""

from __future__ import annotations

import fnmatch
import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml

HERE = Path(__file__).resolve().parent

FORBIDDEN = -32001      # server-defined error code used in this lab for "not permitted"
INVALID_PARAMS = -32602
METHOD_NOT_FOUND = -32601


def load_policy(path: str | Path = HERE / "policy.yaml") -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _schema(**props: dict) -> dict:
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


TOOL_DEFS = {
    "notes_search": {"description": "Search note titles.",
                     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
                                     "required": ["query"], "additionalProperties": False}},
    "notes_read": {"description": "Read one note by id.", "inputSchema": _schema(id={"type": "string"})},
    "notes_write": {"description": "Create or replace a note.", "inputSchema": _schema(id={"type": "string"}, text={"type": "string"})},
    "notes_delete": {"description": "Delete a note.", "inputSchema": _schema(id={"type": "string"})},
    "notes_export": {"description": "Export all notes.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
}


@dataclass
class Session:
    user: str
    role: str | None


@dataclass
class NotesServer:
    policy: dict = field(default_factory=load_policy)
    enforce_calls: bool = True     # False = the classic bug: filter the list only
    audit: list[dict[str, Any]] = field(default_factory=list)
    store: dict[str, str] = field(default_factory=lambda: {
        "notes://public/welcome": "Welcome",
        "notes://team/roadmap": "Roadmap: secret launch in Q3",
        "notes://admin/payroll": "Payroll table",
    })

    # ---------------------------------------------------------------- policy decisions
    def _role(self, session: Session) -> dict | None:
        return self.policy["roles"].get(session.role) if session.role else None

    def allowed_tool(self, session: Session, tool: str) -> bool:
        role = self._role(session)
        return bool(role) and tool in role.get("tools", []) and tool in TOOL_DEFS

    def allowed_resource(self, session: Session, uri: str) -> bool:
        role = self._role(session)
        if not role:
            return False
        norm = normalize_uri(uri)
        return norm is not None and any(fnmatch.fnmatchcase(norm, pat) for pat in role.get("resources", []))

    def limit(self, session: Session, tool: str, key: str, default: int) -> int:
        role = self._role(session) or {}
        return int(role.get("limits", {}).get(tool, {}).get(key, default))

    # ---------------------------------------------------------------- JSON-RPC entry point
    def handle(self, session: Session, request: dict[str, Any]) -> dict[str, Any]:
        rid, method, params = request.get("id"), request.get("method"), request.get("params") or {}
        try:
            if method == "tools/list":
                tools = [{"name": n, **d} for n, d in TOOL_DEFS.items() if self.allowed_tool(session, n)]
                return _ok(rid, {"tools": tools})
            if method == "resources/list":
                res = [{"uri": u} for u in sorted(self.store) if self.allowed_resource(session, u)]
                return _ok(rid, {"resources": res})
            if method == "tools/call":
                return self._call(session, rid, params)
            if method == "resources/read":
                return self._read(session, rid, params)
            return _err(rid, METHOD_NOT_FOUND, "method not found")
        except ValueError as exc:
            return _err(rid, INVALID_PARAMS, str(exc))

    def _call(self, session: Session, rid: Any, params: dict) -> dict:
        tool, args = params.get("name", ""), params.get("arguments") or {}
        if self.enforce_calls and not self.allowed_tool(session, tool):
            self._log(session, "tools/call", tool, "deny")
            return _err(rid, FORBIDDEN, f"tool {tool!r} is not permitted for this session")
        if tool not in TOOL_DEFS:
            return _err(rid, INVALID_PARAMS, "unknown tool")
        self._validate(tool, args)
        self._log(session, "tools/call", tool, "allow")
        if tool == "notes_search":
            n = min(int(args.get("limit", 10)), self.limit(session, tool, "max_results", 10))
            hits = [u for u in sorted(self.store) if args["query"].lower() in u.lower() and self.allowed_resource(session, u)]
            return _ok(rid, {"content": [{"type": "text", "text": "\n".join(hits[:n])}]})
        if tool == "notes_read":
            return self._read(session, rid, {"uri": args["id"]})
        if tool == "notes_write":
            self.store[args["id"]] = args["text"]
            return _ok(rid, {"content": [{"type": "text", "text": "saved"}]})
        if tool == "notes_delete":
            self.store.pop(args["id"], None)
            return _ok(rid, {"content": [{"type": "text", "text": "deleted"}]})
        return _ok(rid, {"content": [{"type": "text", "text": f"{len(self.store)} notes exported"}]})

    def _read(self, session: Session, rid: Any, params: dict) -> dict:
        uri = params.get("uri", "")
        if not self.allowed_resource(session, uri):
            self._log(session, "resources/read", uri, "deny")
            return _err(rid, FORBIDDEN, "resource is not permitted for this session")
        norm = normalize_uri(uri)
        self._log(session, "resources/read", norm or uri, "allow")
        if norm not in self.store:
            return _err(rid, INVALID_PARAMS, "no such resource")
        return _ok(rid, {"contents": [{"uri": norm, "text": self.store[norm]}]})

    @staticmethod
    def _validate(tool: str, args: dict) -> None:
        schema = TOOL_DEFS[tool]["inputSchema"]
        extra = set(args) - set(schema["properties"])
        if extra:
            raise ValueError(f"unexpected arguments {sorted(extra)}")
        for req in schema.get("required", []):
            if req not in args:
                raise ValueError(f"missing argument {req}")

    def _log(self, session: Session, method: str, target: str, decision: str) -> None:
        self.audit.append({"user": session.user, "role": session.role, "method": method, "target": target, "decision": decision})


def normalize_uri(uri: str) -> str | None:
    """Resolve '..' and percent-encoding so notes://public/../admin/payroll cannot match a public pattern."""
    if not uri.startswith("notes://"):
        return None
    path = posixpath.normpath(unquote(uri[len("notes://"):]))
    if path.startswith("..") or path.startswith("/"):
        return None
    return "notes://" + path


def _ok(rid: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
