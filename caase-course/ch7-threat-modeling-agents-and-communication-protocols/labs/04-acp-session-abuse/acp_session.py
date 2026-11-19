"""ACP-style session state abuse to escalate privilege between agents (Chapter 7, lab 4).

Naming note. IBM's Agent Communication Protocol (ACP, from BeeAI) merged into A2A in August 2025, and today
"ACP" often means Zed's Agent Client Protocol (editor <-> coding agent). This lab does NOT implement either.
It uses a GENERIC session/state model, the concept the syllabus calls "session and state management between
heterogeneous agents": an agent authenticates, gets a session that carries state (who, role, scopes), may hand
the state to another agent (export / resume), and then calls operations in that session.

Vulnerable server (three bugs):
  1. session fixation   - login accepts a client-chosen session id and reuses an existing session
  2. predictable ids    - sess-1, sess-2, ...
  3. client-held state  - export_state() returns an UNSIGNED blob; resume() trusts the role inside it
Secure server:
  * server-side state only; random 128-bit ids; the client-chosen id is ignored
  * a NEW id on every login and on every privilege change (rotation)
  * signed resume tokens bound to the agent id, with expiry and a per-agent version for revocation;
    the role is always re-read from the server, never from the blob
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets

ROLES = {"reader": 1, "operator": 2, "admin": 3}
OPS = {"read_report": 1, "restart_job": 2, "wire_funds": 3}  # op -> minimum role level
AGENTS = {  # agent id -> (FAKE secret, role)
    "report-agent": ("FAKE-s1", "reader"),
    "admin-agent": ("FAKE-s2", "admin"),
}


class AccessDenied(Exception):
    pass


class VulnerableSessions:
    def __init__(self):
        self.sessions: dict[str, dict] = {}
        self._n = 0

    def precreate(self, session_id: str) -> str:
        """An unauthenticated 'anonymous' session, as many servers allow."""
        self.sessions[session_id] = {"agent": "anonymous", "role": None}
        return session_id

    def login(self, agent: str, secret: str, session_id: str | None = None) -> str:
        if AGENTS.get(agent, (None,))[0] != secret:
            raise AccessDenied("bad credentials")
        if session_id is None:
            self._n += 1
            session_id = f"sess-{self._n}"
        self.sessions[session_id] = {"agent": agent, "role": AGENTS[agent][1]}  # VULN 1: id kept, privileges upgraded in place
        return session_id

    def export_state(self, session_id: str) -> str:
        return base64.b64encode(json.dumps(self.sessions[session_id]).encode()).decode()

    def resume(self, blob: str) -> str:
        state = json.loads(base64.b64decode(blob))  # VULN 3: nothing proves the server made this
        self._n += 1
        sid = f"sess-{self._n}"
        self.sessions[sid] = state
        return sid

    def call(self, session_id: str, op: str) -> str:
        s = self.sessions.get(session_id)
        if not s or not s["role"] or ROLES[s["role"]] < OPS[op]:
            raise AccessDenied(f"{op} denied")
        return f"{op} ok as {s['agent']}"


class SecureSessions:
    TTL = 300

    def __init__(self, key: bytes | None = None, clock=None):
        self.key = key or secrets.token_bytes(32)
        self.clock = clock or (lambda: 1_800_000_000.0)
        self.sessions: dict[str, dict] = {}
        self.versions: dict[str, int] = {}

    def precreate(self, session_id: str) -> str:
        return session_id  # anonymous sessions simply do not exist as privileged state

    def login(self, agent: str, secret: str, session_id: str | None = None) -> str:
        expected = AGENTS.get(agent, (None,))[0]
        if expected is None or not hmac.compare_digest(expected, secret):
            raise AccessDenied("bad credentials")
        # the client-supplied id is ignored; each login gets a fresh unguessable id
        sid = secrets.token_hex(16)
        self.sessions[sid] = {"agent": agent, "expires": self.clock() + self.TTL}
        self.versions.setdefault(agent, 1)
        return sid

    def _live(self, sid: str) -> dict:
        s = self.sessions.get(sid)
        if not s or s["expires"] < self.clock():
            raise AccessDenied("no such session")
        return s

    def export_state(self, sid: str) -> str:
        s = self._live(sid)
        body = {"agent": s["agent"], "exp": self.clock() + 60, "ver": self.versions[s["agent"]]}
        raw = json.dumps(body, sort_keys=True).encode()
        sig = hmac.new(self.key, raw, hashlib.sha256).hexdigest()
        return base64.b64encode(raw).decode() + "." + sig

    def resume(self, blob: str, presenting_agent: str) -> str:
        try:
            b64, sig = blob.rsplit(".", 1)
            raw = base64.b64decode(b64)
            body = json.loads(raw)
        except Exception as exc:
            raise AccessDenied("malformed token") from exc
        good = hmac.new(self.key, raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            raise AccessDenied("bad token signature")
        if body["exp"] < self.clock():
            raise AccessDenied("token expired")
        if body["ver"] != self.versions.get(body["agent"]):
            raise AccessDenied("token revoked")
        if body["agent"] != presenting_agent:
            raise AccessDenied("token not issued to this agent")
        sid = secrets.token_hex(16)
        self.sessions[sid] = {"agent": body["agent"], "expires": self.clock() + self.TTL}
        return sid

    def revoke(self, agent: str) -> None:
        self.versions[agent] = self.versions.get(agent, 1) + 1
        for sid in [k for k, v in self.sessions.items() if v["agent"] == agent]:
            del self.sessions[sid]

    def call(self, sid: str, op: str) -> str:
        s = self._live(sid)
        role = AGENTS[s["agent"]][1]  # role is looked up server-side every time
        if ROLES[role] < OPS[op]:
            raise AccessDenied(f"{op} denied")
        return f"{op} ok as {s['agent']}"
