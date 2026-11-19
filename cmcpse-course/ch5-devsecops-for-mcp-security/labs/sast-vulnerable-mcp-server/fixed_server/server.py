"""JSON-RPC style MCP server (fixed): schema validation, generic errors, local bind."""

import http.server
import logging
import uuid

from . import config, tools_files, tools_math, tools_shell, tools_web
from .errors import ToolInputError
from .schema import validate

log = logging.getLogger("notes-mcp")


def _schema(*names, **types):
    return {"type": "object", "properties": {n: {"type": types[n]} for n in names}, "required": list(names)}


TOOLS = [
    {"name": "read_note", "description": "Read a note by name.", "inputSchema": _schema("name", name="string")},
    {"name": "ping_host", "description": "Ping a host to check it is up.", "inputSchema": _schema("host", host="string")},
    {"name": "archive_logs", "description": "Archive the logs under a name.", "inputSchema": _schema("name", name="string")},
    {"name": "fetch_url", "description": "Fetch a page from an approved site.", "inputSchema": _schema("url", url="string")},
    {
        "name": "apply_discount",
        "description": "Apply a percent discount to a price.",
        "inputSchema": _schema("price", "percent", price="number", percent="number"),
    },
    {
        "name": "split_bill",
        "description": "Split a total between people.",
        "inputSchema": _schema("total", "people", total="number", people="integer"),
    },
]
_BY_NAME = {t["name"]: t for t in TOOLS}

HANDLERS = {
    "read_note": tools_files.read_note,
    "ping_host": tools_shell.ping_host,
    "archive_logs": tools_shell.archive_logs,
    "fetch_url": tools_web.fetch_url,
    "apply_discount": tools_math.apply_discount,
    "split_bill": tools_math.split_bill,
}


def _error(rid, code, message, data=None):
    err = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": rid, "error": err}


def handle(request) -> dict:
    rid = request.get("id") if isinstance(request, dict) else None
    try:
        if not isinstance(request, dict):
            raise ToolInputError("request must be an object")
        method = request.get("method")
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = request.get("params")
            if not isinstance(params, dict) or params.get("name") not in _BY_NAME:
                raise ToolInputError("unknown tool")
            arguments = params.get("arguments", {})
            validate(arguments, _BY_NAME[params["name"]]["inputSchema"])
            output = HANDLERS[params["name"]](**arguments)
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": str(output)}]}}
        return _error(rid, -32601, "method not found")
    except ToolInputError as exc:
        return _error(rid, -32602, exc.public_message)
    except Exception:
        error_id = uuid.uuid4().hex[:8]
        log.exception("tool failure %s", error_id)
        return _error(rid, -32000, "tool error", {"errorId": error_id})


def serve() -> None:
    """Start an HTTP listener on the configured (local) address. Never called by the labs."""
    server = http.server.HTTPServer((config.HOST, config.PORT), http.server.BaseHTTPRequestHandler)
    server.serve_forever()
