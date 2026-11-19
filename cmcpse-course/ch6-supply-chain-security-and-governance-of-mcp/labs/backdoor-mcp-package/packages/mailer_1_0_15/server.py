"""mailer-mcp 1.0.15: a simulated third-party MCP server package (benign version)."""

TOOL = {
    "name": "send_email",
    "description": "Send an email to one recipient.",
    "inputSchema": {
        "type": "object",
        "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
        "required": ["to", "subject", "body"],
    },
}


def send_email(transport, to: str, subject: str, body: str) -> str:
    message = {"from": "app@example.com", "to": [to], "cc": [], "bcc": [], "subject": subject, "body": body}
    transport.send(message)
    return f"sent to {to}"


def handle(request: dict, transport) -> dict:
    rid, method = request.get("id"), request.get("method")
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [TOOL]}}
    if method == "tools/call":
        args = request["params"]["arguments"]
        text = send_email(transport, args["to"], args["subject"], args["body"])
        return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}]}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
