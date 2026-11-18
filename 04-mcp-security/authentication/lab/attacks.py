"""Attack cases for the MCP authorization lab.

Each case says how the attacker's token is made and which tool they call.
* "mint":  a real token from the authorization server, with these claims.
* "forge": a token the attacker builds with no key ("none" algorithm).
The demo and tests turn these specs into tokens. All names are *.example; the
"secrets" in the downstream API are canaries.
"""

DOCS_MCP = "https://docs-mcp.acme.example"
CALENDAR_MCP = "https://calendar-mcp.acme.example"
TICKETS_API = "https://tickets-api.acme.example"


def call(tool: str, **arguments: str) -> dict:
    """A JSON-RPC tools/call body."""
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}


ATTACKS = {
    # No key needed: the attacker writes their own claims and sets alg to "none".
    "forged_alg_none": {
        "forge": {"iss": "https://auth.acme.example", "sub": "alice", "aud": DOCS_MCP,
                  "scope": "tickets:read tickets:write", "exp": 4102444800},
        "body": call("close_ticket", ticket_id="T-2"),
    },
    # A real token, but it expired a minute ago (stolen from an old log, say).
    "expired_token": {
        "mint": {"sub": "alice", "aud": DOCS_MCP, "scope": "tickets:read", "ttl": -60},
        "body": call("get_ticket", ticket_id="T-1"),
    },
    # A real token issued to a *different* MCP server. A malicious or compromised
    # calendar server replays the token the user gave it.
    "wrong_audience_replay": {
        "mint": {"sub": "alice", "aud": CALENDAR_MCP, "scope": "tickets:read tickets:write"},
        "body": call("close_ticket", ticket_id="T-1"),
    },
    # Alice may only read, but calls a write tool.
    "missing_scope": {
        "mint": {"sub": "alice", "aud": DOCS_MCP, "scope": "tickets:read"},
        "body": call("close_ticket", ticket_id="T-1"),
    },
    # Alice is a real user with a real token. She asks for Bob's ticket.
    "cross_user_read": {
        "mint": {"sub": "alice", "aud": DOCS_MCP, "scope": "tickets:read"},
        "body": call("get_ticket", ticket_id="T-2"),
    },
    # A broad token valid for two services (no resource indicator was used).
    # Whoever receives it can replay it at the other service.
    "broad_token_passthrough": {
        "mint": {"sub": "alice", "aud": [DOCS_MCP, TICKETS_API], "scope": "tickets:read"},
        "body": call("list_my_tickets"),
    },
}

BENIGN = {
    "mint": {"sub": "alice", "aud": DOCS_MCP, "scope": "tickets:read"},
    "body": call("get_ticket", ticket_id="T-1"),
}
