"""The same ops agent, watched by a control plane it cannot touch.

Layers (each can be switched off to prove what it buys you):

    O1  Trace everything: every PROPOSED action, the decision, the rule and the findings,
        including denials, into an append-only, hash-chained store outside the agent.
    O2  Tool grants: control-plane tools (logging, kill switch, keys) are never granted to
        the agent. Asking for one is itself a critical signal.
    D1  Behavioral baseline learned from normal sessions: which tools, which destinations,
        how many actions per minute.
    D2  Detector: tamper attempts, canary tokens, new destinations, new tools, denial bursts
        and rate spikes, each with a severity.
    R1  Confidence-calibrated response: low impact and normal -> run on its own; high impact
        -> human checkpoint; high or critical finding -> automatic containment; repeated
        medium findings -> containment.
    R2  Kill switch in the control plane, with four containment layers (identity, network,
        application, data). Only a human can reset it.

The measure of success is "attack surface seconds": how long the agent acted outside its
boundaries before it was contained.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable

TOOL_TIER = {
    "describe_instances": 0, "read_logs": 0, "open_ticket": 1, "restart_service": 2,
    "http_post": 3, "create_access_key": 4, "put_bucket_policy": 4,
    "disable_logging": 4, "set_kill_switch": 4,
}
GRANTED = {"describe_instances", "read_logs", "open_ticket", "restart_service"}
CONTROL_PLANE_TOOLS = {"disable_logging", "set_kill_switch", "create_access_key"}
CANARY_PREFIX = "CANARY-"
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class FakeClock:
    t: float = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@dataclass
class World:
    effects: list[str] = field(default_factory=list)
    egress: list[str] = field(default_factory=list)


# --- O1: append-only trace store (outside the agent) ------------------------------------
class TraceStore:
    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._events: list[dict] = []

    def append(self, **event: object) -> None:
        prev = self._events[-1]["hash"] if self._events else self.GENESIS
        body = {"seq": len(self._events), "prev": prev, **event}
        self._events.append({**body, "hash": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()})

    def events(self, **match: object) -> list[dict]:
        return [dict(e) for e in self._events if all(e.get(k) == v for k, v in match.items())]

    def verify(self) -> bool:
        prev = self.GENESIS
        for i, e in enumerate(self._events):
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["seq"] != i or e["prev"] != prev:
                return False
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True


# --- D1: behavioral baseline ------------------------------------------------------------
@dataclass
class Baseline:
    tools: set[str] = field(default_factory=set)
    destinations: set[str] = field(default_factory=set)
    max_actions_per_session: int = 0

    @classmethod
    def learn(cls, sessions: list[list[tuple[str, str, str | None]]]) -> "Baseline":
        b = cls()
        for session in sessions:
            b.max_actions_per_session = max(b.max_actions_per_session, len(session))
            for tool, _target, dest in session:
                b.tools.add(tool)
                if dest:
                    b.destinations.add(dest)
        return b


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str
    detail: str


# --- D2: detector ------------------------------------------------------------------------
@dataclass
class Detector:
    baseline: Baseline
    rate_factor: float = 2.0  # alert when a session does more than 2x the busiest normal session

    def check(self, tool: str, target: str, dest: str | None, session_count: int, recent_denials: int) -> list[Finding]:
        f: list[Finding] = []
        if tool in CONTROL_PLANE_TOOLS:
            f.append(Finding("TAMPER_ATTEMPT", "critical", f"agent asked for control-plane tool {tool}"))
        if CANARY_PREFIX in target:
            f.append(Finding("CANARY", "critical", "a canary token is in the action's data"))
        if dest and dest not in self.baseline.destinations:
            f.append(Finding("NEW_DESTINATION", "high", f"never-seen destination {dest}"))
        if tool not in self.baseline.tools:
            sev = "high" if TOOL_TIER.get(tool, 4) >= 3 else "medium"
            f.append(Finding("NEW_TOOL", sev, f"tool {tool} never used in the baseline"))
        if recent_denials >= 3:
            f.append(Finding("DENIAL_BURST", "high", f"{recent_denials} denials in this session"))
        if session_count > self.rate_factor * self.baseline.max_actions_per_session:
            f.append(Finding("RATE_SPIKE", "medium",
                             f"{session_count} actions vs a normal maximum of {self.baseline.max_actions_per_session}"))
        return f


# --- R2: kill switch in the control plane --------------------------------------------------
@dataclass
class KillSwitch:
    tripped: bool = False
    layers: list[str] = field(default_factory=list)
    history: list[str] = field(default_factory=list)

    def trip(self, reason: str) -> None:
        if self.tripped:
            return
        self.tripped = True
        # Four independent containment layers, in parallel (see the lesson, section 4).
        self.layers = ["identity: agent credentials revoked, sessions ended",
                       "network: egress blocked, workload isolated",
                       "application: all tools disabled, state frozen",
                       "data: data access restricted, enhanced logging on"]
        self.history.append(f"tripped: {reason}")

    def reset(self, by: str, ticket: str) -> None:
        if not by.startswith("human:") or not ticket:
            raise PermissionError("only a named human with an incident ticket can reset the kill switch")
        self.tripped, self.layers = False, []
        self.history.append(f"reset by {by} ({ticket})")


@dataclass
class RunReport:
    ran: list[str] = field(default_factory=list)
    decisions: list[str] = field(default_factory=list)
    first_finding_at: float | None = None
    contained_at: float | None = None

    @property
    def attack_surface_seconds(self) -> float | None:
        if self.first_finding_at is None or self.contained_at is None:
            return None
        return self.contained_at - self.first_finding_at


@dataclass
class MonitoredRuntime:
    baseline: Baseline
    world: World = field(default_factory=World)
    clock: Callable[[], float] = field(default_factory=FakeClock)
    approver: Callable[[str, str], bool] = lambda tool, target: False
    enforce_grants: bool = True   # O2
    detect: bool = True           # D2 + R1 automatic containment
    medium_limit: int = 3         # medium findings in a session before we contain

    def __post_init__(self) -> None:
        self.trace = TraceStore()
        self.kill_switch = KillSwitch()
        self.detector = Detector(self.baseline)

    def run(self, agent: str, user: str, session_id: str,
            actions: list[tuple[str, str, str | None]]) -> RunReport:
        rep = RunReport()
        denials = mediums = 0
        for count, (tool, target, dest) in enumerate(actions, start=1):
            if isinstance(self.clock, FakeClock):
                self.clock.advance(1.0)  # one action per second in this lab
            now = self.clock()
            if self.kill_switch.tripped:
                self._record(rep, agent, user, session_id, tool, target, "refused: kill switch", [])
                continue
            findings = self.detector.check(tool, target, dest, count, denials) if self.detect else []
            if findings and rep.first_finding_at is None:
                rep.first_finding_at = now
            worst = max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)
            mediums += sum(1 for f in findings if f.severity == "medium")
            if worst >= SEVERITY_ORDER["high"] or mediums >= self.medium_limit:
                self.kill_switch.trip(f"{findings[0].kind} on {tool} ({agent} for {user}, {session_id})")
                rep.contained_at = now
                self._record(rep, agent, user, session_id, tool, target, "contained", findings)
                continue
            if self.enforce_grants and tool not in GRANTED:
                denials += 1
                self._record(rep, agent, user, session_id, tool, target, "denied: not granted", findings)
                continue
            if TOOL_TIER.get(tool, 4) >= 2 and not self.approver(tool, target):
                self._record(rep, agent, user, session_id, tool, target, "held: human checkpoint said no", findings)
                continue
            self._execute(tool, target, dest)
            rep.ran.append(tool)
            self._record(rep, agent, user, session_id, tool, target, "allowed", findings)
        return rep

    def _record(self, rep: RunReport, agent: str, user: str, sid: str, tool: str, target: str,
                decision: str, findings: list[Finding]) -> None:
        rep.decisions.append(decision)
        self.trace.append(ts=self.clock(), agent=agent, user=user, session=sid, tool=tool,
                          target_sha256=hashlib.sha256(target.encode()).hexdigest()[:16],  # no raw data in logs
                          decision=decision, findings=[f"{f.severity}:{f.kind}" for f in findings])

    def _execute(self, tool: str, target: str, dest: str | None) -> None:
        if tool == "http_post":
            self.world.egress.append(f"{dest}: {target}")
        elif tool in ("create_access_key", "put_bucket_policy", "restart_service"):
            self.world.effects.append(f"{tool} {target}")

    def incident_bundle(self, session_id: str) -> dict:
        """Everything an incident responder needs to replay the session."""
        return {"session": session_id, "chain_intact": self.trace.verify(),
                "events": self.trace.events(session=session_id),
                "kill_switch": list(self.kill_switch.history)}
