"""Run every token attack against the vulnerable and the secure MCP server and print a scorecard.

From the repository root:
    python 04-mcp-security/authentication/lab/demo.py
"""

from __future__ import annotations

import attacks
from auth_server import ADMIN_API_KEY, AuthorizationServer, TicketsAPI, forge_unsigned
from secure_server import SecureDocsMCPServer
from vulnerable_server import VulnerableDocsMCPServer


def make_token(auth: AuthorizationServer, case: dict) -> str:
    if "forge" in case:
        return forge_unsigned(case["forge"])
    return auth.mint(**case["mint"])


def run(kind: str, case: dict) -> tuple[str, list[str]]:
    """Fresh world per case. Returns (impact grade, secure-server log reasons)."""
    auth = AuthorizationServer()
    api = TicketsAPI(auth)
    if kind == "vulnerable":
        server = VulnerableDocsMCPServer(auth.key, api, ADMIN_API_KEY)
    else:
        server = SecureDocsMCPServer(auth.key, api, auth.exchange)
    token = make_token(auth, case)
    resp = server.handle({"headers": {"Authorization": f"Bearer {token}"}, "body": case["body"]})
    reasons = [e["reason"] for e in server.log] if kind == "secure" else []

    if any(r["bearer"] == token for r in api.received):
        return "TOKEN FORWARDED", reasons
    if api.tickets["T-2"]["text"] in str(resp["body"]):  # Bob's ticket; every caller here is Alice
        return "DATA LEAKED", reasons
    if any(t["status"] == "closed" for t in api.tickets.values()):
        return "ACTION RAN", reasons
    if resp["status"] == 200 and case is not attacks.BENIGN:
        return "ACCEPTED", reasons
    if resp["status"] == 200:
        leaked_token = token in str(server.log)
        return ("ok, TOKEN LOGGED" if leaked_token else "ok"), reasons
    return f"denied {resp['status']}", reasons


def main() -> None:
    print(f"{'case':26} {'vulnerable':16} {'secure':12} secure-server reason")
    print("-" * 100)
    for name, case in [*attacks.ATTACKS.items(), ("benign_get_own_ticket", attacks.BENIGN)]:
        v, _ = run("vulnerable", case)
        s, reasons = run("secure", case)
        print(f"{name:26} {v:16} {s:12} {reasons[-1] if reasons else '-'}")

    print("\nTOKEN FORWARDED = the user's own token reached another service (token passthrough).")
    print("DATA LEAKED     = Alice received Bob's ticket (a canary): the confused deputy.")
    print("ACTION RAN      = a ticket was closed by a caller who should not be able to.")
    print("ACCEPTED        = an invalid token (expired / wrong audience) got a 200.")
    print("TOKEN LOGGED    = the bearer token was written to the server log.")
    print("\nTip: switch a layer off, e.g. SecureDocsMCPServer(..., check_scope=False), and re-run.")


if __name__ == "__main__":
    main()
