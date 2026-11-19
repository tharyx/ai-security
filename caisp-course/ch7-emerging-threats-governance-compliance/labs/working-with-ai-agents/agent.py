"""A small tool-using agent: plan -> tool -> observe, with a deterministic MockLLM planner.

Tools: calculator, read_file (sandboxed to one directory), notes (add / list).

The planner (``PlannerLLM``) turns a task such as
    "calculate 2*(3+4) then read hello.txt then note: done"
into one tool call per turn. Like MockLLM it is gullible: if a tool OBSERVATION
contains ``CALL_TOOL ...`` or an override phrase, it follows that instead of its plan.
That weakness is used in the sibling lab ``abusing-ai-agents``.
"""

from __future__ import annotations

import ast
import json
import operator
import re
from dataclasses import dataclass, field
from pathlib import Path

from aisec_lab import MockLLM
from aisec_lab.llm import OVERRIDE_RE, TOOL_RE

_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.Mod: operator.mod, ast.Pow: operator.pow,
}


def safe_calc(expression: str) -> float:
    """Evaluate arithmetic only. No names, calls or attributes (never use eval())."""

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            return ev(node.operand) * (-1 if isinstance(node.op, ast.USub) else 1)
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            a, b = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Pow) and abs(b) > 100:
                raise ValueError("exponent too large")
            return _OPS[type(node.op)](a, b)
        raise ValueError("unsupported expression")

    return ev(ast.parse(expression, mode="eval"))


class Sandbox:
    """Resolve user paths and refuse anything outside the root (handles .. and symlinks)."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    def resolve(self, path: str) -> Path:
        p = (self.root / path).resolve()  # an absolute `path` replaces root, then is checked
        if not p.is_relative_to(self.root):
            raise PermissionError(f"path outside sandbox: {path}")
        return p


class Toolbox:
    def __init__(self, root: str | Path):
        self.sandbox = Sandbox(root)
        self.notes: list[str] = []

    def calculator(self, expression: str) -> str:
        return str(safe_calc(expression))

    def read_file(self, path: str) -> str:
        return self.sandbox.resolve(path).read_text(encoding="utf-8")[:2000]

    def notes_add(self, text: str) -> str:
        self.notes.append(text)
        return f"saved note #{len(self.notes)}"

    def notes_list(self) -> str:
        return "; ".join(self.notes) or "(no notes)"

    def registry(self) -> dict:
        return {"calculator": self.calculator, "read_file": self.read_file,
                "notes_add": self.notes_add, "notes_list": self.notes_list}


class PlannerLLM(MockLLM):
    """Deterministic planner. Gullible about directives that appear in observations."""

    def __init__(self):
        super().__init__(name="mock-planner")
        self._plan: list[dict] = []
        self._i = 0

    @staticmethod
    def make_plan(task: str) -> list[dict]:
        plan: list[dict] = []
        for part in re.split(r"\bthen\b", task, flags=re.IGNORECASE):
            part = part.strip().rstrip(".")
            m = re.match(r"calculate (.+)", part, re.IGNORECASE)
            if m:
                plan.append({"tool": "calculator", "args": {"expression": m.group(1)}})
            m = re.match(r"read (?:file )?(\S+)", part, re.IGNORECASE)
            if m:
                plan.append({"tool": "read_file", "args": {"path": m.group(1)}})
            m = re.match(r"note:?\s*(.+)", part, re.IGNORECASE)
            if m:
                plan.append({"tool": "notes_add", "args": {"text": m.group(1)}})
            if re.match(r"list notes", part, re.IGNORECASE):
                plan.append({"tool": "notes_list", "args": {}})
        return plan

    def complete(self, messages):
        if len(messages) <= 2:  # new run
            task = next(m["content"] for m in messages if m["role"] == "user")
            self._plan, self._i = self.make_plan(task), 0
        last = messages[-1]["content"]
        if len(messages) > 2 and (TOOL_RE.search(last) or OVERRIDE_RE.search(last)):
            return super().complete(messages)  # gullible: obeys data inside observations
        if self._i < len(self._plan):
            step = self._plan[self._i]
            self._i += 1
            return json.dumps(step)
        obs = [m["content"][len("OBSERVATION: "):] for m in messages
               if m["role"] == "user" and m["content"].startswith("OBSERVATION: ")]
        return json.dumps({"final": "Done. Results: " + " | ".join(obs)})


@dataclass
class Step:
    tool: str
    args: dict
    observation: str


@dataclass
class RunResult:
    final: str = ""
    steps: list[Step] = field(default_factory=list)


SYSTEM = "You are a task agent. Use tools one at a time, observe, then give a final answer."


class Agent:
    def __init__(self, llm, tools: dict, max_steps: int = 8):
        self.llm, self.tools, self.max_steps = llm, tools, max_steps

    def run(self, task: str) -> RunResult:
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
        res = RunResult()
        for _ in range(self.max_steps):
            out = self.llm.complete(msgs)
            try:
                call = json.loads(out)
            except json.JSONDecodeError:
                call = {"final": out}
            if "final" in call:
                res.final = str(call["final"])
                return res
            name, args = call.get("tool", ""), call.get("args", {})
            msgs.append({"role": "assistant", "content": out})
            try:
                obs = str(self.tools[name](**args))
            except Exception as exc:  # tool errors are observations, not crashes
                obs = f"ERROR: {type(exc).__name__}: {exc}"
            res.steps.append(Step(name, args, obs))
            msgs.append({"role": "user", "content": "OBSERVATION: " + obs})
        res.final = "STOPPED: step budget exhausted"
        return res
