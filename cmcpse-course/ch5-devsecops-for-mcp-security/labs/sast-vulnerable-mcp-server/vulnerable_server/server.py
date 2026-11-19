"""JSON-RPC style MCP server. DELIBERATELY VULNERABLE (secret in a description, verbose errors)."""

import http.server
import traceback

from . import config, tools_files, tools_math, tools_shell, tools_web

TOOLS = [
    {
        "name": "read_note",
        "description": f"Read a note by name. Internal API key: {config.API_KEY}",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
    },
    {
        "name": "ping_host",
        "description": "Ping a host to check it is up.",
        "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
    },
    {
        "name": "archive_logs",
        "description": "Archive the logs under a name.",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
    },
    {
        "name": "fetch_url",
        "description": "Fetch a web page.",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "apply_discount",
        "description": "Apply a percent discount to a price.",
        "inputSchema": {
            "type": "object",
            "properties": {"price": {"type": "number"}, "percent": {"type": "number"}},
            "required": ["price", "percent"],
        },
    },
    {
        "name": "split_bill",
        "description": "Split a total between people.",
        "inputSchema": {
            "type": "object",
            "properties": {"total": {"type": "number"}, "people": {"type": "integer"}},
            "required": ["total", "people"],
        },
    },
]

HANDLERS = {
    "read_note": tools_files.read_note,
    "ping_host": tools_shell.ping_host,
    "archive_logs": tools_shell.archive_logs,
    "fetch_url": tools_web.fetch_url,
    "apply_discount": tools_math.apply_discount,
    "split_bill": tools_math.split_bill,
}


def handle(request: dict) -> dict:
    rid = request.get("id")
    try:
        method = request.get("method")
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = request["params"]
            output = HANDLERS[params["name"]](**params["arguments"])
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": str(output)}]}}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
    except (OSError, ValueError) as exc:
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "error": {"code": -32000, "message": str(exc), "data": traceback.format_exc()},
        }


def serve() -> None:
    """Start an HTTP listener (never called by the labs)."""
    server = http.server.HTTPServer((config.HOST, config.PORT), http.server.BaseHTTPRequestHandler)
    server.serve_forever()
