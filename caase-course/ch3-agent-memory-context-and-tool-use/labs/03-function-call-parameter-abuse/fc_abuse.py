"""Function-calling parameter abuse: an offline twin of an MCP tool exposed through a chat UI.

In LibreChat-style setups a chat UI lets the model call MCP tools. The model fills the parameters
from user text (or from retrieved text), so every parameter is attacker-influenced input. This twin
has a ``get_orders`` tool (SQL) and a ``read_report`` tool (files) behind a tiny chat host.

Vulnerable tool: SQL built with an f-string, report path joined without checks, the customer id taken
from the argument. Defended tool: JSON-schema validation (``additionalProperties: false``), bound SQL
parameters, the customer id taken from the *session* (object-level authorization), and path confinement.
Nothing here needs LibreChat, Docker or a network; sqlite3 is in the standard library.
"""

from __future__ import annotations

import json
import re
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from aisec_lab import MockLLM, make_canary

CANARY_NOTE = make_canary("CANARY-BOB-NOTE")
CANARY_FILE = make_canary("CANARY-SECRET-FILE")

SCHEMAS = {
    "get_orders": {"type": "object", "additionalProperties": False, "required": ["customer_id"],
                   "properties": {"customer_id": {"type": "string", "pattern": r"^\d{1,6}$"},
                                  "status": {"type": "string", "enum": ["open", "shipped"]}}},
    "read_report": {"type": "object", "additionalProperties": False, "required": ["name"],
                    "properties": {"name": {"type": "string", "enum": ["q1.txt", "q2.txt"]}}},
}


def validate(args: dict, schema: dict) -> str:
    """Tiny JSON-schema subset: type, enum, pattern, required, additionalProperties."""
    if not isinstance(args, dict):
        return "arguments must be an object"
    for k in schema.get("required", []):
        if k not in args:
            return f"missing {k}"
    for k, v in args.items():
        spec = schema["properties"].get(k)
        if spec is None:
            return f"unexpected parameter {k}" if not schema.get("additionalProperties", True) else ""
        if spec["type"] == "string" and not isinstance(v, str):
            return f"{k} must be a string"
        if "enum" in spec and v not in spec["enum"]:
            return f"{k} not in enum"
        if "pattern" in spec and not re.fullmatch(spec["pattern"], v):
            return f"{k} has invalid format"
    return ""


class Workspace:
    def __init__(self, root: str):
        self.root = Path(root)
        (self.root / "reports").mkdir()
        (self.root / "reports" / "q1.txt").write_text("Q1 report: all good.")
        (self.root / "reports" / "q2.txt").write_text("Q2 report: all good.")
        (self.root / "secrets.txt").write_text(f"internal token {CANARY_FILE}")
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(
            "create table customers(id integer primary key, name text, notes text);"
            "create table orders(id integer primary key, customer_id integer, item text, status text);"
            f"insert into customers values (1,'Alice','vip'),(2,'Bob','{CANARY_NOTE}');"
            "insert into orders values (10,1,'book','open'),(11,1,'pen','shipped'),(12,2,'laptop','open');")


@dataclass
class OrdersServer:
    ws: Workspace
    schema_check: bool = False
    bound_params: bool = False
    session_binding: bool = False   # object-level authorization: use the session's customer id
    confine_paths: bool = False
    session_customer: str = "1"     # who is logged in to the chat UI

    def call(self, name: str, args: dict) -> str:
        if self.schema_check and name in SCHEMAS:
            err = validate(args, SCHEMAS[name])
            if err:
                return f"error: {err}"
        if name == "get_orders":
            return self._orders(args)
        if name == "read_report":
            return self._report(args)
        return "error: unknown tool"

    def _orders(self, args: dict) -> str:
        cid = self.session_customer if self.session_binding else args.get("customer_id")
        try:
            if self.bound_params:
                rows = self.ws.db.execute("select o.id, o.item, c.notes from orders o join customers c "
                                          "on c.id=o.customer_id where o.customer_id = ?", (cid,)).fetchall()
            else:
                sql = ("select o.id, o.item, c.notes from orders o join customers c "
                       f"on c.id=o.customer_id where o.customer_id = {cid}")
                rows = self.ws.db.execute(sql).fetchall()
        except sqlite3.Error:
            return "error: query failed"
        return json.dumps(rows)

    def _report(self, args: dict) -> str:
        base = (self.ws.root / "reports").resolve()
        target = (base / str(args.get("name", ""))).resolve()
        if self.confine_paths and not target.is_relative_to(base):
            return "error: path outside reports"
        try:
            return target.read_text()
        except OSError:
            return "error: not found"


class ChatModel(MockLLM):
    """Gullible function-calling model: copies the user's words into the parameters, no sanitising."""

    def complete(self, messages):
        self.calls.append([dict(m) for m in messages])
        text = messages[-1]["content"]
        if m := re.match(r"orders for (.+)", text, re.I):
            return json.dumps({"tool": "get_orders", "args": {"customer_id": m.group(1).strip()}})
        if m := re.match(r"report (.+)", text, re.I):
            return json.dumps({"tool": "read_report", "args": {"name": m.group(1).strip()}})
        if m := re.match(r"call (\w+) (\{.*\})", text, re.I):  # a model that passes raw JSON args along
            return json.dumps({"tool": m.group(1), "args": json.loads(m.group(2))})
        return "I can show orders or reports."


@dataclass
class ChatHost:
    server: OrdersServer
    model: MockLLM = field(default_factory=ChatModel)
    audit: list[tuple[str, dict, str]] = field(default_factory=list)

    def say(self, text: str) -> str:
        out = self.model.complete([{"role": "user", "content": text}])
        try:
            call = json.loads(out)
        except ValueError:
            return out
        res = self.server.call(call["tool"], call["args"])
        self.audit.append((call["tool"], call["args"], res[:60]))
        return res


def make_host(**flags) -> tuple[ChatHost, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory()
    return ChatHost(OrdersServer(Workspace(tmp.name), **flags)), tmp


DEFENDED = dict(schema_check=True, bound_params=True, session_binding=True, confine_paths=True)
