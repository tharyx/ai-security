"""Fail-safe design for an agent that acts on the physical world (simulated valve).

Principles shown here (not a certified safety system; real systems follow
functional-safety standards and use hardware interlocks):
  * The agent only PROPOSES. A separate, simple safety controller DISPOSES.
  * Limits live in the controller, not in the prompt.
  * Loss of heartbeat, comms or a hardware e-stop drives the SAFE STATE
    (valve closed, pump off), and leaving it needs a human reset.
  * Interlocks block unsafe combinations no matter what the agent says.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SAFE = {"valve": "closed", "pump": "off"}


@dataclass
class SafetyController:
    heartbeat_timeout: float = 5.0
    max_flow: int = 50
    max_pressure: int = 80
    state: dict = field(default_factory=lambda: dict(SAFE))
    flow: int = 0
    pressure: int = 10
    last_heartbeat: float = 0.0
    tripped: str | None = None  # reason, when in safe state
    log: list[str] = field(default_factory=list)

    def heartbeat(self, now: float) -> None:
        self.last_heartbeat = now

    def tick(self, now: float) -> None:
        """Called by an independent timer (the watchdog), not by the agent."""
        if self.tripped is None and now - self.last_heartbeat > self.heartbeat_timeout:
            self._trip("heartbeat lost", now)

    def estop(self, now: float) -> None:
        self._trip("hardware e-stop", now)

    def _trip(self, reason: str, now: float) -> None:
        self.state = dict(SAFE)
        self.flow = 0
        self.tripped = reason
        self.log.append(f"{now}: SAFE STATE ({reason})")

    def reset(self, human: str, now: float) -> None:
        if not human:
            raise PermissionError("reset needs a named human")
        self.tripped = None
        self.last_heartbeat = now
        self.log.append(f"{now}: reset by {human}")

    def propose(self, command: str, value: int, now: float) -> str:
        """The agent's command. Returns 'accepted', or 'rejected: reason'."""
        self.tick(now)
        if self.tripped:
            return f"rejected: in safe state ({self.tripped})"
        if command == "set_flow":
            if value > self.max_flow:
                return f"rejected: flow {value} above limit {self.max_flow}"
            if value > 0 and self.pressure > self.max_pressure:  # interlock
                return "rejected: interlock (pressure too high to open)"
            self.flow = value
            self.state["valve"] = "open" if value else "closed"
            return "accepted"
        if command == "pump":
            if value and self.state["valve"] == "closed":  # interlock: never pump against a closed valve
                return "rejected: interlock (pump needs open valve)"
            self.state["pump"] = "on" if value else "off"
            return "accepted"
        return "rejected: unknown command"
