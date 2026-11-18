"""A deliberately vulnerable remote MCP server ("docs-mcp") that calls a downstream Tickets API.

It receives HTTP-like requests: {"headers": {...}, "body": <JSON-RPC tools/call>}.
It checks only that the token "looks valid", forwards the user's own token to the
downstream API, and uses a shared admin key for most downstream calls.

DO NOT copy this pattern. Every line marked VULN is one of the mistakes this lab
teaches you to find.

Run the whole scorecard from the repository root:
    python 04-mcp-security/authentication/lab/demo.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class VulnerableDocsMCPServer:
    def __init__(self, signing_key: bytes, tickets_api: Any, admin_api_key: str) -> None:
        self.key = signing_key
        self.tickets = tickets_api
        self.admin_api_key = admin_api_key  # VULN 1: one shared, all-powerful downstream credential
        self.log: list[str] = []

    def _authenticate(self, token: str) -> dict[str, Any] | None:
        try:
            head, body, mac = token.split(".")
            header, claims = json.loads(_b64d(head)), json.loads(_b64d(body))
        except (ValueError, json.JSONDecodeError):
            return None
        # VULN 2: the token tells us which algorithm to use. "none" means "skip the signature".
        if header.get("alg") == "none":
            return claims
        expected = hmac.new(self.key, f"{head}.{body}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(mac)):
            return None
        # VULN 3: no check of iss, aud or exp. A token for any audience, from any time, is fine.
        return claims

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        auth = request.get("headers", {}).get("Authorization", "")
        # VULN 4: the bearer token is written to the log.
        self.log.append(f"request auth={auth} body={json.dumps(request.get('body'))}")
        claims = self._authenticate(auth.removeprefix("Bearer "))
        if claims is None:
            return {"status": 401, "headers": {}, "body": {"error": "unauthorized"}}
        token = auth.removeprefix("Bearer ")
        params = request["body"]["params"]
        tool, args = params["name"], params.get("arguments", {})
        # VULN 5: no scope check. Any authenticated caller may call any tool.
        try:
            if tool == "get_ticket":
                # VULN 6: confused deputy. We fetch with OUR admin key whatever ticket the caller names.
                result: Any = self.tickets.get_ticket(args["ticket_id"], api_key=self.admin_api_key)
            elif tool == "close_ticket":
                result = self.tickets.close_ticket(args["ticket_id"], api_key=self.admin_api_key)
            elif tool == "list_my_tickets":
                # VULN 7: token passthrough. The user's token is forwarded to another service.
                result = self.tickets.list_tickets(bearer=token)
            else:
                return {"status": 400, "headers": {}, "body": {"error": "unknown tool"}}
        except PermissionError as exc:
            return {"status": 502, "headers": {}, "body": {"error": f"downstream refused: {exc}"}}
        return {"status": 200, "headers": {}, "body": {"result": result}}
