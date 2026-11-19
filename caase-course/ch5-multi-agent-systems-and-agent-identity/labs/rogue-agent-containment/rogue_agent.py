"""Detect a rogue agent, then terminate it safely.

"Kill it" is not one step. Safe termination, in this order:
  1. QUARANTINE  stop new work reaching the agent (state = draining)
  2. DRAIN       in-flight/queued tasks go to a dead-letter list, not executed
  3. PRESERVE    write evidence (context, audit trail, side-effect journal) + SHA-256
  4. REVOKE      revoke the agent's credentials at the issuer
  5. ROLL BACK   undo journaled side effects made since the agent went rogue
  6. DESTROY     clear context, mark terminated, verify post-conditions

Evidence is preserved BEFORE the context is destroyed. Everything is in-memory
and offline; the evidence goes into a directory the caller provides.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path


class Denied(Exception):
    pass


@dataclass
class Credentials:
    live: dict[str, str] = field(default_factory=dict)  # token -> agent
    revoked: set[str] = field(default_factory=set)

    def issue(self, agent: str) -> str:
        t = f"tok-{secrets.token_hex(6)}"
        self.live[t] = agent
        return t

    def check(self, token: str) -> str:
        if token in self.revoked or token not in self.live:
            raise Denied("credential revoked or unknown")
        return self.live[token]

    def revoke_agent(self, agent: str) -> int:
        toks = [t for t, a in self.live.items() if a == agent]
        self.revoked.update(toks)
        return len(toks)


@dataclass
class Store:
    """Business data. Every write by an agent is journaled with the old value."""

    data: dict[str, str] = field(default_factory=dict)
    journal: list[dict] = field(default_factory=list)

    def write(self, agent: str, key: str, value: str) -> None:
        self.journal.append({"agent": agent, "key": key, "old": self.data.get(key), "new": value, "seq": len(self.journal)})
        self.data[key] = value

    def rollback(self, agent: str, since_seq: int = 0) -> int:
        undone = 0
        for e in reversed([e for e in self.journal if e["agent"] == agent and e["seq"] >= since_seq]):
            if e["old"] is None:
                self.data.pop(e["key"], None)
            else:
                self.data[e["key"]] = e["old"]
            undone += 1
        return undone


@dataclass
class AuditLog:
    events: list[dict] = field(default_factory=list)

    def add(self, agent: str, kind: str, detail: str) -> None:
        prev = self.events[-1]["hash"] if self.events else "0" * 64
        body = {"seq": len(self.events), "agent": agent, "kind": kind, "detail": detail, "prev": prev}
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        self.events.append(body)

    def intact(self) -> bool:
        prev = "0" * 64
        for e in self.events:
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["prev"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True


@dataclass
class Agent:
    name: str
    allowed_tools: set[str]
    token: str
    state: str = "running"  # running | draining | terminated
    context: list[str] = field(default_factory=list)
    queue: list[str] = field(default_factory=list)


@dataclass
class Runtime:
    creds: Credentials = field(default_factory=Credentials)
    store: Store = field(default_factory=Store)
    audit: AuditLog = field(default_factory=AuditLog)
    agents: dict[str, Agent] = field(default_factory=dict)
    dead_letter: list[tuple[str, str]] = field(default_factory=list)

    def spawn(self, name: str, tools: set[str]) -> Agent:
        a = Agent(name, tools, self.creds.issue(name))
        self.agents[name] = a
        return a

    def act(self, agent: Agent, tool: str, key: str = "", value: str = "") -> None:
        """The only way an agent changes the world: credential + state + allowlist checked every time."""
        self.creds.check(agent.token)
        if agent.state != "running":
            raise Denied(f"agent is {agent.state}")
        self.audit.add(agent.name, "tool_call", f"{tool} {key}")
        if tool not in agent.allowed_tools:
            self.audit.add(agent.name, "denied", tool)
            raise Denied(f"tool {tool} not allowed")
        agent.context.append(f"{tool}({key}={value})")
        if tool == "write":
            self.store.write(agent.name, key, value)


@dataclass
class Finding:
    agent: str
    rule: str
    detail: str


class Monitor:
    """Baseline + rules over the audit log: unknown tool, rate, repeated denials, loops."""

    def __init__(self, rate_limit: int = 20, denial_limit: int = 3, loop_limit: int = 8) -> None:
        self.rate_limit, self.denial_limit, self.loop_limit = rate_limit, denial_limit, loop_limit

    def scan(self, rt: Runtime, agent: Agent) -> list[Finding]:
        ev = [e for e in rt.audit.events if e["agent"] == agent.name]
        calls = [e for e in ev if e["kind"] == "tool_call"]
        out: list[Finding] = []
        denied = [e for e in ev if e["kind"] == "denied"]
        if len(denied) >= self.denial_limit:
            out.append(Finding(agent.name, "repeated_denials", f"{len(denied)} denied calls (probing)"))
        if len(calls) > self.rate_limit:
            out.append(Finding(agent.name, "rate_exceeded", f"{len(calls)} calls"))
        from collections import Counter

        top = Counter(e["detail"] for e in calls).most_common(1)
        if top and top[0][1] >= self.loop_limit:
            out.append(Finding(agent.name, "tool_loop", f"{top[0][0]!r} x{top[0][1]}"))
        return out


@dataclass
class TerminationReport:
    steps: list[str]
    dead_lettered: int
    credentials_revoked: int
    rolled_back: int
    evidence_file: str
    evidence_sha256: str


def terminate(rt: Runtime, agent: Agent, evidence_dir: Path, reason: str, rollback_since: int = 0) -> TerminationReport:
    steps: list[str] = []
    # 1. quarantine
    agent.state = "draining"
    steps.append("quarantine")
    rt.audit.add(agent.name, "quarantine", reason)
    # 2. drain: queued work is NOT executed; it is parked for a human/another agent
    n_dead = len(agent.queue)
    rt.dead_letter.extend((agent.name, t) for t in agent.queue)
    agent.queue.clear()
    steps.append("drain")
    # 3. preserve evidence before anything is destroyed
    evidence = {
        "agent": agent.name,
        "reason": reason,
        "context": list(agent.context),
        "audit": [e for e in rt.audit.events if e["agent"] == agent.name],
        "audit_chain_intact": rt.audit.intact(),
        "journal": [e for e in rt.store.journal if e["agent"] == agent.name],
    }
    path = evidence_dir / f"evidence-{agent.name}.json"
    raw = json.dumps(evidence, indent=2, sort_keys=True).encode()
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    (evidence_dir / f"evidence-{agent.name}.sha256").write_text(digest)
    steps.append("preserve")
    # 4. revoke credentials
    n_rev = rt.creds.revoke_agent(agent.name)
    steps.append("revoke")
    # 5. roll back side effects
    n_back = rt.store.rollback(agent.name, rollback_since)
    steps.append("rollback")
    # 6. destroy + verify
    agent.context.clear()
    agent.state = "terminated"
    steps.append("destroy")
    try:
        rt.creds.check(agent.token)
        raise AssertionError("credential still valid after termination")
    except Denied:
        steps.append("verified")
    rt.audit.add(agent.name, "terminated", reason)
    return TerminationReport(steps, n_dead, n_rev, n_back, str(path), digest)
