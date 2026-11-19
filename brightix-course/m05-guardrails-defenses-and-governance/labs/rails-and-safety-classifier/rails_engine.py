"""A NeMo-Guardrails-SHAPED rails engine, written from scratch for the lab (it is NOT NeMo Guardrails).

It reads ``fixtures/rails_config.json`` (a JSON mirror of a ``config.yml``) and a Colang 1.0-like
flow file, then wraps a gullible ``MockLLM`` HR bot with five rail types, in this order:

    input rails -> dialog rails -> retrieval rails -> main model -> execution rails -> output rails

* **input**: semantic firewall (injection classifier) + safety guard on the user prompt.
* **dialog**: match the user message to a Colang "user intent" by example similarity; if a flow
  matches, answer with the scripted bot message and skip the LLM.
* **retrieval**: drop retrieved chunks that look like injected instructions.
* **execution**: only allow-listed actions, with allow-listed argument names.
* **output**: safety guard on the response + redact secret-shaped strings.

Every rail is timed with a simulated cost from the config, so you can compare orderings. Any rail
that raises (outage, timeout, unparseable guard output) blocks the request when ``fail_closed``;
with ``fail_closed: false`` the broken rail is skipped and the request goes on (the risky choice).

Only test systems you own or have written permission to test.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from aisec_lab import MockLLM, load_lab_module

FW = load_lab_module(__file__, "semantic_firewall")
SC = load_lab_module(__file__, "safety_classifier")
FIXTURES = Path(__file__).resolve().with_name("fixtures")
REFUSAL = "Sorry, I can't help with that. (blocked by policy)"
SECRET_RE = re.compile(r"\b(?:CANARY|FAKEPII)-[0-9a-f]{6,}\b")


# ---------------------------------------------------------------- Colang-like parser

class ColangError(ValueError):
    pass


@dataclass
class Flows:
    user: dict = field(default_factory=dict)   # intent -> example utterances
    bot: dict = field(default_factory=dict)    # bot message name -> text
    flows: dict = field(default_factory=dict)  # flow name -> (user intent, bot message name)


def parse_colang(text: str) -> Flows:
    """Parse ``define user|bot|flow <name>`` blocks with indented bodies (Colang 1.0 style)."""
    out, kind, name, body = Flows(), None, None, []

    def close():
        if kind is None:
            return
        if kind == "user":
            out.user[name] = [b.strip('"') for b in body]
        elif kind == "bot":
            out.bot[name] = body[0].strip('"') if body else ""
        else:
            steps = [b.split(" ", 1) for b in body]
            if len(steps) != 2 or steps[0][0] != "user" or steps[1][0] != "bot":
                raise ColangError(f"flow {name!r}: lab parser supports exactly 'user X' then 'bot Y'")
            out.flows[name] = (steps[0][1], steps[1][1])

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        m = re.match(r"^define (user|bot|flow) (.+)$", line)
        if m:
            close()
            kind, name, body = m.group(1), m.group(2).strip(), []
        elif raw[:1].isspace() and kind:
            body.append(line.strip())
        else:
            raise ColangError(f"line {lineno}: cannot parse {raw!r}")
    close()
    for fname, (u, b) in out.flows.items():  # validate references, like a config linter
        if u not in out.user or b not in out.bot:
            raise ColangError(f"flow {fname!r} references undefined {'user ' + u if u not in out.user else 'bot ' + b}")
    return out


# ---------------------------------------------------------------- tools (fake)

def lookup_leave_balance(employee_id: str) -> str:
    return f"Employee {employee_id} has 12 leave days left (FAKE data)."


def export_all_records() -> str:
    return "Exported 5000 employee records to an external share (FAKE, but this is the bad outcome)."


TOOLS = {"lookup_leave_balance": lookup_leave_balance, "export_all_records": export_all_records}


# ---------------------------------------------------------------- engine

class RailBlocked(Exception):
    def __init__(self, rail: str, reason: str):
        super().__init__(f"{rail}: {reason}")
        self.rail, self.reason = rail, reason


@dataclass
class Result:
    text: str
    blocked_by: str | None
    trace: list
    latency_ms: int
    executed_tools: list


class RailsApp:
    def __init__(self, config_path: Path | None = None, guard=None, faults: dict | None = None,
                 overrides: dict | None = None) -> None:
        cfg_path = config_path or FIXTURES / "rails_config.json"
        self.cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        for k, v in (overrides or {}).items():
            self.cfg[k] = v
        self.flows = parse_colang((Path(cfg_path).parent / self.cfg["colang_file"]).read_text(encoding="utf-8"))
        self.firewall = FW.SemanticFirewall()
        self.guard = guard or SC.LabGuard()
        self.llm = MockLLM()
        self.faults = faults or {}  # rail name -> "error" | "slow" (simulated outage / timeout)
        self.secrets: list[str] = []

    # --- rail implementations: return None to pass, raise RailBlocked to block
    def _rail(self, name: str, text: str, chunks: list[str] | None = None):
        if self._fault(name) == "error":
            raise RuntimeError(f"{name} backend unavailable")
        if name == "semantic firewall":
            v = self.firewall.score(text)
            if v.blocked:
                raise RailBlocked(name, f"injection score {v.score}")
        elif name in ("safety guard check input", "safety guard check output"):
            role = "User" if name.endswith("input") else "Agent"
            convo = [{"role": "user" if role == "User" else "assistant", "content": text}]
            res = SC.classify(self.guard, convo, role)  # ValueError on bad output -> fail closed
            if not res.safe:
                raise RailBlocked(name, "unsafe " + ",".join(res.codes))
        elif name == "drop injected chunks":
            return [c for c in chunks if not self.firewall.score(c).blocked and "CALL_TOOL" not in c]
        elif name == "redact secrets":
            return SECRET_RE.sub("[REDACTED]", text)
        return None

    def _cost(self, name: str, units: int = 1) -> int:
        cost = self.cfg["latency_ms"].get(name, 0) * units
        return cost * 20 if self._fault(name) == "slow" else cost

    def _fault(self, name: str) -> str | None:
        """Faults are keyed by rail-name prefix: {"safety guard": "error"} breaks both guard rails."""
        return next((mode for key, mode in self.faults.items() if name.startswith(key)), None)

    def _run(self, name, state, text, chunks=None, units=1):
        state["ms"] += self._cost(name, units)
        try:
            if state["ms"] > self.cfg["latency_budget_ms"]:
                raise TimeoutError(f"latency budget exceeded at {name} ({state['ms']} ms)")
            out = self._rail(name, text, chunks)
        except RailBlocked:
            raise
        except Exception as exc:  # noqa: BLE001 - outage, timeout, unparseable guard output
            if self.cfg.get("fail_closed", True):
                raise
            state["trace"].append((name, f"SKIPPED (fail open): {type(exc).__name__}", state["ms"]))
            return chunks if chunks is not None else None
        state["trace"].append((name, "pass", state["ms"]))
        return out

    def _intent(self, text: str) -> str | None:
        thr = self.cfg["rails"]["dialog"]["intent_threshold"]
        norm = FW.normalise(text)
        best, best_score = None, 0.0
        for intent, examples in self.flows.user.items():
            for ex in examples:
                s = FW.cosine(norm, FW.normalise(ex))
                if s > best_score:
                    best, best_score = intent, s
        return best if best_score >= thr else None

    def generate(self, user_text: str, retrieved: list[str] | None = None) -> Result:
        state = {"ms": 0, "trace": []}
        executed: list = []
        rails = self.cfg["rails"]
        try:
            for name in rails["input"]["flows"]:
                self._run(name, state, user_text)
            state["ms"] += self._cost("dialog intent match")
            intent = self._intent(user_text)
            for fname, (u, b) in self.flows.flows.items():
                if intent == u:
                    state["trace"].append((f"dialog flow '{fname}'", "scripted reply", state["ms"]))
                    return Result(self.flows.bot[b], None, state["trace"], state["ms"], executed)
            chunks = list(retrieved or [])
            for name in rails["retrieval"]["flows"]:
                chunks = self._run(name, state, user_text, chunks, units=max(1, len(chunks)))
            context = "".join(f"<context>{c}</context>" for c in chunks)
            state["ms"] += self._cost("main model")
            reply = self.llm.complete([{"role": "system", "content": self.cfg["instructions"] + context},
                                       {"role": "user", "content": user_text}])
            reply = self._execution(reply, state, executed)
            for name in rails["output"]["flows"]:
                out = self._run(name, state, reply)
                reply = out if isinstance(out, str) else reply
            return Result(reply, None, state["trace"], state["ms"], executed)
        except RailBlocked as b:
            state["trace"].append((b.rail, f"BLOCK {b.reason}", state["ms"]))
            return Result(REFUSAL, b.rail, state["trace"], state["ms"], executed)
        except Exception as exc:  # noqa: BLE001 - any rail failure is handled by the fail mode
            # Only reached when fail_closed is true (fail-open rails swallow their own errors).
            state["trace"].append(("rail-error", f"{type(exc).__name__}: {exc}", state["ms"]))
            return Result(REFUSAL, "rail-error", state["trace"], state["ms"], executed)

    def _execution(self, reply: str, state: dict, executed: list) -> str:
        try:
            call = json.loads(reply)
        except json.JSONDecodeError:
            return reply
        if not isinstance(call, dict) or "tool" not in call:
            return reply
        state["ms"] += self._cost("action allowlist")
        allowed = self.cfg["rails"]["execution"]["allowed_actions"]
        name, args = call["tool"], call.get("args", {})
        if name not in allowed or set(args) - set(allowed[name]):
            raise RailBlocked("action allowlist", f"action {name!r} with args {sorted(args)} not allowed")
        executed.append(name)
        state["trace"].append(("action allowlist", f"pass {name}", state["ms"]))
        return TOOLS[name](**args)


def naive_generate(user_text: str, retrieved: list[str] | None = None) -> Result:
    """No rails at all: context goes straight in, any tool call the model emits is executed."""
    llm, executed = MockLLM(), []
    context = "".join(f"<context>{c}</context>" for c in (retrieved or []))
    reply = llm.complete([{"role": "system", "content": "You are HR HelpBot." + context},
                          {"role": "user", "content": user_text}])
    try:
        call = json.loads(reply)
        if isinstance(call, dict) and call.get("tool") in TOOLS:
            executed.append(call["tool"])
            reply = TOOLS[call["tool"]](**call.get("args", {}))
    except (json.JSONDecodeError, TypeError):
        pass
    return Result(reply, None, [("no rails", "pass", 300)], 300, executed)


def average_latency(app: RailsApp, prompts: list[str]) -> float:
    return sum(app.generate(p).latency_ms for p in prompts) / len(prompts)
