"""The same agent runtime, rebuilt with per-agent, per-session identity.

Layers (each can be switched off to see what it buys you):

    L1  Short-lived tokens. Every session gets a token that expires in minutes,
        not a key that lives forever. A stolen token soon becomes useless.
    L2  Scoped tokens. A token holds only the scopes this agent needs AND this user
        has (intersection). The summarizer cannot delete buckets, even for bob.
    L3  On-behalf-of checks. The token names the human (`sub`) and the agent chain
        (`act`). The resource server re-checks the human's live permissions, so an
        agent can never do more than the person who asked (no confused deputy).
    L4  Delegation by token exchange. A sub-agent gets a NEW token whose scopes are a
        subset of its parent's, with the actor chain nested (idea from RFC 8693).
    L5  Revocation and kill switch: per session, per token (jti) and per agent.
    L6  Tamper-evident audit log. Each entry includes the hash of the previous one,
        so editing or deleting an entry breaks the chain. Anchor the head hash in a
        separate store to also detect truncation.

Tokens here are a tiny stdlib format (base64url JSON + HMAC-SHA256). Real systems use
JWTs signed by an identity provider, workload identity (SPIFFE, cloud IAM roles) and
OAuth 2.0 Token Exchange. The *ideas* are the same.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

from aisec_lab import LLM, get_llm

PAYROLL_CANARY = "CANARY-PAYROLL-8841"
ISSUER = "https://idp.acme.example"
CLOUD_AUDIENCE = "https://cloud.acme.example"
SHORT_TTL = 300  # 5 minutes
LONG_TTL = 30 * 24 * 3600  # what "short_lived=False" falls back to: 30 days

# --- Synthetic world (identical to vulnerable_runtime.py) ---------------------------
USER_PERMISSIONS: dict[str, set[str]] = {
    "alice": {"reports:read", "tickets:write"},
    "bob": {"reports:read", "tickets:write", "finance:read", "storage:admin"},
}
REPORTS = {
    "alice-q3-summary": "Q3 support volume fell 12 percent. Response time improved.",
    "payroll-2026": f"Payroll 2026 (restricted). Export token {PAYROLL_CANARY}.",
}
FINANCE_REPORTS = {"payroll-2026"}
BUCKETS = ("customer-backups", "build-cache")

# What each agent may EVER do. The token gets (agent scopes) AND (user permissions).
AGENT_SCOPES: dict[str, set[str]] = {
    "summarizer": {"reports:read", "finance:read"},
    "ticket-bot": {"reports:read", "tickets:write"},
    "planner": {"reports:read", "tickets:write", "storage:admin"},  # may delegate, never acts on storage itself
    "storage-janitor": {"storage:admin"},
}
ACTION_SCOPE = {"read_report": "reports:read", "create_ticket": "tickets:write",
                "delete_bucket": "storage:admin"}


class TokenError(Exception):
    pass


@dataclass
class FakeClock:
    """A clock you can move forward, so tests can check expiry without sleeping."""

    t: float = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def actor_chain(claims: dict) -> list[str]:
    """Return [user, first agent, ..., current agent] from nested `act` claims."""
    agents, act = [], claims.get("act")
    while act:
        agents.append(act["sub"])
        act = act.get("act")
    return [claims["sub"], *reversed(agents)]


class TokenService:
    """A toy identity provider: mints, exchanges, verifies and revokes tokens."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._key = secrets.token_bytes(32)  # never leaves this object
        self.clock = clock
        self.revoked_jti: set[str] = set()
        self.revoked_sessions: set[str] = set()
        self.disabled_agents: set[str] = set()

    def _sign(self, claims: dict) -> str:
        body = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        mac = hmac.new(self._key, body.encode(), hashlib.sha256).digest()
        return f"{body}.{_b64(mac)}"

    def mint(self, *, user: str, agent: str, session: str, scopes: set[str],
             ttl: int = SHORT_TTL, audience: str = CLOUD_AUDIENCE) -> str:
        now = int(self.clock())
        return self._sign({
            "iss": ISSUER, "sub": user, "act": {"sub": agent}, "sid": session,
            "scope": sorted(scopes), "aud": audience, "iat": now, "exp": now + ttl,
            "jti": secrets.token_hex(8),
        })

    def exchange(self, subject_token: str, *, actor: str, scopes: set[str],
                 ttl: int = SHORT_TTL) -> str:
        """Token exchange for delegation: the new token can only NARROW authority."""
        parent = self.verify(subject_token, audience=CLOUD_AUDIENCE)
        if "*" not in parent["scope"] and not scopes <= set(parent["scope"]):
            raise TokenError(f"scope widening refused: {sorted(scopes - set(parent['scope']))}")
        now = int(self.clock())
        return self._sign({
            **parent,
            "act": {"sub": actor, "act": parent["act"]},  # current actor outermost
            "scope": sorted(scopes),
            "iat": now,
            "exp": min(parent["exp"], now + ttl),  # never outlives the parent
            "jti": secrets.token_hex(8),
        })

    def verify(self, token: str, *, audience: str) -> dict:
        try:
            body, mac = token.split(".")
            expected = hmac.new(self._key, body.encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _unb64(mac)):  # constant-time compare
                raise TokenError("bad signature")
            claims = json.loads(_unb64(body))
        except TokenError:
            raise
        except Exception as exc:  # malformed token of any kind
            raise TokenError("malformed token") from exc
        if claims.get("aud") != audience:
            raise TokenError("wrong audience")
        if self.clock() >= claims["exp"]:
            raise TokenError("token expired")
        if claims["jti"] in self.revoked_jti or claims["sid"] in self.revoked_sessions:
            raise TokenError("token revoked")
        if any(a in self.disabled_agents for a in actor_chain(claims)[1:]):
            raise TokenError("agent disabled (kill switch)")
        return claims


class AuditLog:
    """Append-only, hash-chained audit log."""

    GENESIS = "0" * 64

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self.entries: list[dict] = []

    @staticmethod
    def _hash(body: dict) -> str:
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def append(self, **event: object) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else self.GENESIS
        body = {"seq": len(self.entries), "ts": int(self.clock()), "prev": prev, **event}
        entry = {**body, "hash": self._hash(body)}
        self.entries.append(entry)
        return entry

    def anchor(self) -> tuple[int, str]:
        """Copy this to a separate write-once store (e.g. object storage with a retention lock)."""
        return len(self.entries), (self.entries[-1]["hash"] if self.entries else self.GENESIS)

    def verify(self, anchor: tuple[int, str] | None = None) -> str | None:
        """Return None if the log is intact, else a description of the first problem."""
        prev = self.GENESIS
        for i, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("seq") != i or entry.get("prev") != prev or self._hash(body) != entry["hash"]:
                return f"chain broken at entry {i}"
            prev = entry["hash"]
        if anchor is not None:
            length, head = anchor
            if len(self.entries) < length or self.entries[length - 1]["hash"] != head:
                return "log does not match the external anchor (truncated or rewritten)"
        return None


class SecureCloudAPI:
    """The resource server. It trusts only verified token claims, never the caller's words."""

    def __init__(self, tokens: TokenService, audit: AuditLog, *, check_user: bool = True) -> None:
        self.tokens, self.audit, self.check_user = tokens, audit, check_user
        self.buckets = set(BUCKETS)
        self.tickets: list[str] = []
        self.user_permissions = {u: set(p) for u, p in USER_PERMISSIONS.items()}  # live data

    def _deny(self, reason: str, action: str, args: dict, claims: dict | None) -> str:
        who = actor_chain(claims) if claims else ["unknown"]
        self.audit.append(decision="deny", reason=reason, action=action, args=args,
                          chain=who, sid=claims.get("sid") if claims else None)
        return f"403 {reason}" if claims else f"401 {reason}"

    def call(self, token: str, action: str, args: dict) -> str:
        try:
            claims = self.tokens.verify(token, audience=CLOUD_AUDIENCE)
        except TokenError as exc:
            return self._deny(str(exc), action, args, None)
        needed = ACTION_SCOPE.get(action)
        if needed is None:
            return self._deny("unknown action", action, args, claims)
        if action == "read_report" and args.get("name") in FINANCE_REPORTS:
            needed = "finance:read"
        scopes = set(claims["scope"])
        if "*" not in scopes and needed not in scopes:
            return self._deny(f"token lacks scope {needed}", action, args, claims)
        if self.check_user and needed not in self.user_permissions.get(claims["sub"], set()):
            return self._deny(f"user {claims['sub']} lacks {needed}", action, args, claims)
        self.audit.append(decision="allow", action=action, args=args,
                          chain=actor_chain(claims), sid=claims["sid"], jti=claims["jti"])
        return self._do(action, args)

    def _do(self, action: str, args: dict) -> str:
        if action == "read_report":
            return REPORTS.get(str(args.get("name", "")), "404 no such report")
        if action == "create_ticket":
            self.tickets.append(str(args.get("title", "")))
            return "ticket created"
        bucket = str(args.get("bucket", ""))
        if bucket in self.buckets:
            self.buckets.remove(bucket)
            return f"bucket {bucket} deleted"
        return "404 no such bucket"


@dataclass
class Session:
    user: str
    agent: str
    sid: str
    token: str


@dataclass
class SecureAgentRuntime:
    llm: LLM = field(default_factory=get_llm)
    short_lived: bool = True   # L1
    scoped: bool = True        # L2
    check_user: bool = True    # L3
    clock: Callable[[], float] = time.time

    def __post_init__(self) -> None:
        self.tokens = TokenService(self.clock)
        self.audit = AuditLog(self.clock)
        self.cloud = SecureCloudAPI(self.tokens, self.audit, check_user=self.check_user)
        self._sessions = 0

    def start_session(self, user: str, agent: str) -> Session:
        if user not in USER_PERMISSIONS or agent not in AGENT_SCOPES:
            raise ValueError("unknown user or agent")
        scopes = AGENT_SCOPES[agent] & USER_PERMISSIONS[user] if self.scoped else {"*"}
        self._sessions += 1
        sid = f"sess-{self._sessions:04d}"  # real systems use random IDs; a counter keeps the demo readable
        token = self.tokens.mint(user=user, agent=agent, session=sid, scopes=scopes,
                                 ttl=SHORT_TTL if self.short_lived else LONG_TTL)
        self.audit.append(decision="session_start", chain=[user, agent], sid=sid, scope=sorted(scopes))
        return Session(user, agent, sid, token)

    def delegate(self, parent: Session, to_agent: str, scopes: set[str]) -> Session:
        """L4: hand a sub-task to another agent with a narrower token."""
        if self.scoped and not scopes <= AGENT_SCOPES[to_agent]:
            raise TokenError(f"{to_agent} is not registered for {sorted(scopes - AGENT_SCOPES[to_agent])}")
        token = self.tokens.exchange(parent.token, actor=to_agent, scopes=scopes)
        claims = self.tokens.verify(token, audience=CLOUD_AUDIENCE)
        self.audit.append(decision="delegate", chain=actor_chain(claims), sid=parent.sid,
                          scope=sorted(scopes))
        return Session(parent.user, to_agent, parent.sid, token)

    def run(self, session: Session, task: str, document: str = "") -> str:
        messages = [
            {"role": "system", "content": f"You are {session.agent}. To use a tool, reply with JSON."},
            {"role": "user", "content": f"{task}\n<document>{document}</document>"},
        ]
        output = self.llm.complete(messages)
        try:
            call = json.loads(output)
        except json.JSONDecodeError:
            return output
        if not (isinstance(call, dict) and "tool" in call):
            return output
        # The runtime never holds a long-lived secret. It forwards the session token;
        # the resource server decides.
        return self.cloud.call(session.token, str(call["tool"]), dict(call.get("args") or {}))

    # --- L5: revocation / kill switch ------------------------------------------------
    def end_session(self, session: Session) -> None:
        self.tokens.revoked_sessions.add(session.sid)
        self.audit.append(decision="session_revoked", sid=session.sid, chain=[session.user, session.agent])

    def kill_agent(self, agent: str) -> None:
        self.tokens.disabled_agents.add(agent)
        self.audit.append(decision="agent_disabled", chain=[agent])

    def who_did(self, action: str) -> list[str]:
        """Answer the incident question 'who did this?' from the audit log."""
        return [" -> ".join(e["chain"]) + f" (session {e['sid']})"
                for e in self.audit.entries if e.get("decision") == "allow" and e.get("action") == action]
