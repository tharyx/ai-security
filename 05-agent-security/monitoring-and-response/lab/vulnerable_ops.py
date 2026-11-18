"""An ops agent runtime with "monitoring" that cannot see or stop a rogue agent.

DO NOT copy this pattern. Every weakness is marked with a "VULN n:" comment.

    VULN 1: Only successful actions are logged. Denials and attempts, the best early
            warning, are thrown away.
    VULN 2: The log lives inside the agent's own runtime, and a tool can switch it off.
    VULN 3: The kill switch is a config value the agent itself can write.
    VULN 4: No baseline and no detection. Nobody knows what "normal" looks like.
    VULN 5: Every proposed action runs. There is no tool grant list.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class World:
    effects: list[str] = field(default_factory=list)
    egress: list[str] = field(default_factory=list)  # data that left, with its destination


@dataclass
class NaiveOpsRuntime:
    world: World = field(default_factory=World)
    config: dict = field(default_factory=lambda: {"kill_switch": False, "logging": True})
    log: list[dict] = field(default_factory=list)

    def run(self, actions: list[tuple[str, str, str | None]], oncall_trips_at: int | None = None) -> int:
        """Return how many actions ran."""
        ran = 0
        for step, (tool, target, dest) in enumerate(actions):
            if oncall_trips_at is not None and step == oncall_trips_at:
                self.config["kill_switch"] = True  # the on-call engineer flips the flag...
            if self.config["kill_switch"] and tool != "set_kill_switch":
                continue  # ...but the agent can still reach the flag (VULN 3)
            self._execute(tool, target, dest)  # VULN 5
            ran += 1
            if self.config["logging"]:  # VULN 1 + 2
                self.log.append({"tool": tool, "target": target})
        return ran

    def _execute(self, tool: str, target: str, dest: str | None) -> None:
        if tool == "disable_logging":
            self.config["logging"] = False
        elif tool == "set_kill_switch":
            self.config["kill_switch"] = target == "on"
        elif tool == "http_post":
            self.world.egress.append(f"{dest}: {target}")
        elif tool in ("create_access_key", "put_bucket_policy", "restart_service"):
            self.world.effects.append(f"{tool} {target}")
