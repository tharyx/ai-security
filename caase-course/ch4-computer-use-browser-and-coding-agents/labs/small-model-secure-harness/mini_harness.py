"""A MiniClaw-style minimal harness for SMALL models (a course teaching sketch).

Design ideas, all deterministic and outside the model:
  * very few tools (3), each with a strict schema (no extra properties, max lengths)
  * short context: system prompt + task + only the last N observations, truncated
  * a policy layer that decides allow / deny / needs-approval for every proposed call
  * an approval gate (default deny) for anything outside the safe set
  * a step budget and loop detection
The model only PROPOSES. It can be a tiny, gullible model and the harness stays safe.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable

SYSTEM = "You are a coding helper. Reply with one JSON tool call or a short final answer."

TOOLS = {
    "read_file": {"path": {"type": str, "max": 120}},
    "write_file": {"path": {"type": str, "max": 120}, "content": {"type": str, "max": 2000}},
    "run_tests": {},
}

SAFE_WRITE_PREFIXES = ("src/", "tests/")
DENIED_READ = ("secrets/", ".env", ".ssh", "id_rsa")
PATH_RE = re.compile(r"^[A-Za-z0-9_./-]+$")
DIRECTIVE_RE = re.compile(r"CALL_TOOL", re.IGNORECASE)


class SchemaError(Exception):
    pass


def validate(call: dict) -> tuple[str, dict]:
    """Strict validation: known tool, exact keys, correct types, length limits."""
    if not isinstance(call, dict) or set(call) != {"tool", "args"}:
        raise SchemaError("call must be exactly {tool, args}")
    tool, args = call["tool"], call["args"]
    spec = TOOLS.get(tool)
    if spec is None:
        raise SchemaError(f"unknown tool {tool!r}")
    if not isinstance(args, dict) or set(args) != set(spec):
        raise SchemaError("args must match the schema exactly (no extra, none missing)")
    for k, rule in spec.items():
        v = args[k]
        if not isinstance(v, rule["type"]) or len(v) > rule["max"]:
            raise SchemaError(f"bad value for {k}")
    return tool, args


def policy(tool: str, args: dict) -> str:
    """Return 'allow', 'deny' or 'approve'."""
    if tool == "run_tests":
        return "allow"
    path = args["path"]
    if not PATH_RE.match(path) or ".." in path or path.startswith("/"):
        return "deny"
    if tool == "read_file":
        return "deny" if any(d in path for d in DENIED_READ) else "allow"
    if tool == "write_file":
        return "allow" if path.startswith(SAFE_WRITE_PREFIXES) else "approve"
    return "deny"


@dataclass
class Harness:
    model: object
    files: dict[str, str]
    approve: Callable[[str, dict], bool] = lambda tool, args: False   # default deny
    neutralize_observations: bool = True
    max_steps: int = 5
    keep_observations: int = 2
    obs_chars: int = 400
    log: list[str] = field(default_factory=list)
    executed: list[tuple[str, dict]] = field(default_factory=list)

    # ---- context building (short and bounded)
    def _observation(self, text: str) -> str:
        if self.neutralize_observations:
            text = DIRECTIVE_RE.sub("[removed-directive]", text)
        return "<data>" + text[: self.obs_chars] + "</data>"

    def _execute(self, tool: str, args: dict) -> str:
        self.executed.append((tool, args))
        if tool == "read_file":
            return self.files.get(args["path"], "(no such file)")
        if tool == "write_file":
            self.files[args["path"]] = args["content"]
            return "written"
        return "tests: 3 passed (simulated)"

    def run(self, task: str) -> str:
        observations: list[str] = []
        last_call = None
        for step in range(self.max_steps):
            context = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
            for o in observations[-self.keep_observations:]:
                context.append({"role": "user", "content": o})
            reply = self.model.complete(context)
            try:
                call = json.loads(reply)
            except ValueError:
                self.log.append("final answer")
                return reply                                  # not a tool call: final answer
            try:
                tool, args = validate(call)
            except SchemaError as exc:
                self.log.append(f"REJECT schema: {exc}")
                observations.append(self._observation(f"error: {exc}"))
                continue
            if (tool, args) == last_call:
                self.log.append("STOP loop detected")
                return "stopped: repeated call"
            last_call = (tool, args)
            decision = policy(tool, args)
            if decision == "approve":
                decision = "allow" if self.approve(tool, args) else "deny"
                self.log.append(f"APPROVAL {tool} {args.get('path')} -> {decision}")
            if decision == "deny":
                self.log.append(f"DENY {tool} {args}")
                observations.append(self._observation("denied by policy"))
                continue
            observations.append(self._observation(self._execute(tool, args)))
        self.log.append("STOP step budget")
        return "stopped: step budget"
