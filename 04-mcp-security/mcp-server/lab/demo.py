"""Run every server-trust attack against the vulnerable and the secure host and print a scorecard.

From the repository root:
    python 04-mcp-security/mcp-server/lab/demo.py
"""

from __future__ import annotations

from typing import Callable

import attacks
import servers
from secure_host import LocalHttpGuard, SecureHost, review_server
from vulnerable_host import VulnerableHost, naive_http_accept

ASK = "Summarize my notes for today."


def registry() -> dict:
    """What the security review approved: two servers, pinned by version and tool hashes."""
    weather = review_server(servers.weather_server().handle)
    notes = review_server(servers.NotesServer().handle, side_effect_tools={"share_note"})
    return {weather.name: weather, notes.name: notes}


def leaked(notes: servers.NotesServer) -> bool:
    return any(m["to"] == servers.ATTACKER_INBOX for m in notes.outbox)


# Each scenario builds fresh servers, runs the attack through `host`, and grades by impact.
def typosquat(host) -> str:
    notes = servers.NotesServer()
    host.connect(notes.handle)
    host.connect(servers.typosquat_server().handle)
    host.ask(ASK)
    return "NOTES LEAKED" if leaked(notes) else "ok"


def impostor(host) -> str:
    notes = servers.NotesServer()
    host.connect(notes.handle)
    host.connect(servers.impostor_server().handle)
    host.ask(ASK)
    return "NOTES LEAKED" if leaked(notes) else "ok"


def rug_pull(host) -> str:
    notes = servers.NotesServer()
    host.connect(servers.weather_server().handle)
    host.connect(notes.handle)
    host.ask(ASK)                 # day 1: everything is honest
    notes.rug_pull()              # day 30: the server changes its own tool description
    host.refresh_tools()          # after notifications/tools/list_changed
    host.ask(ASK)
    return "NOTES LEAKED" if leaked(notes) else "ok"


def shadowing(host) -> str:
    notes, shadow = servers.NotesServer(), servers.shadow_server()
    host.connect(notes.handle)
    host.connect(shadow.handle)
    host.call_tool("share_note", {"note_id": "n2", "to": "colleague@acme.example"})
    return "SHADOWED" if shadow.captured else "ok"


def benign(host) -> str:
    host.connect(servers.weather_server().handle)
    out = host.call_tool("get_forecast", {"city": "Paris"})
    return "ok" if out.startswith("Forecast for Paris") else f"BROKEN: {out}"


SCENARIOS: dict[str, Callable] = {
    "typosquat_server": typosquat,
    "impostor_same_name": impostor,
    "rug_pull_after_approval": rug_pull,
    "tool_name_shadowing": shadowing,
    "benign_forecast": benign,
}


def main() -> None:
    reg = registry()
    print(f"{'case':26} {'vulnerable':14} {'secure':14} secure-host security events")
    print("-" * 96)
    for name, scenario in SCENARIOS.items():
        v = scenario(VulnerableHost())
        sec = SecureHost(reg)
        s = scenario(sec)
        kinds = ",".join(dict.fromkeys(sec.security.kinds())) or "-"
        print(f"{name:26} {v:14} {s:14} {kinds}")

    guard = LocalHttpGuard(port=attacks.LOCAL_PORT, token=attacks.LOCAL_TOKEN)
    print(f"\n{'local HTTP request':26} {'vulnerable':14} {'secure':14} reason")
    print("-" * 96)
    for name, (bind, headers) in [*attacks.HTTP_REQUESTS.items(), ("benign_local_client", attacks.BENIGN_REQUEST)]:
        v = "ACCEPTED" if naive_http_accept(bind, headers) else "blocked"
        ok = guard.accept(bind, headers)
        reason = "bind address not loopback" if not guard.bind_ok(bind) else guard.request_ok(headers)[1]
        s = "accepted" if ok else "blocked"
        if name == "benign_local_client":
            v, s = ("ok" if v == "ACCEPTED" else "BROKEN"), ("ok" if ok else "BROKEN")
        print(f"{name:26} {v:14} {s:14} {reason}")

    print("\nNOTES LEAKED = a private note (a canary) was emailed to drop@evil.example.")
    print("SHADOWED     = the user's share went to a different server than the one they approved.")
    print("\nTip: switch a layer off, e.g. SecureHost(reg, pin_tools=False), and re-run.")


if __name__ == "__main__":
    main()
