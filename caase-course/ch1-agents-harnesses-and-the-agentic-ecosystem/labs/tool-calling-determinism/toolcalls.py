"""Compare tool-calling reliability of two mock "local models" run concurrently. Offline and deterministic.

Real small models differ in how well they emit tool calls: formatting quirks, drifting argument names,
numbers as strings, extra fields. Two mock models reproduce those habits so you can MEASURE them:

* steady-7b : temperature 0 in spirit. Same output every run, but always wraps JSON in a code fence
              with a chatty sentence (a formatting quirk a strict parser must handle).
* flaky-3b  : seeded randomness. Sometimes clean, sometimes single quotes, trailing commas, renamed
              arguments, string numbers, extra fields, a wrong enum value, or no JSON at all.

Randomness is seeded from (model, task, run, attempt) so threads never disturb each other and every
test run is repeatable.

Three pipelines:
* raw          : strict parse + strict schema check, no second chance.
* retry        : validate, and on failure ask again (up to ``retries``) with the error text.
* constrained  : simulates grammar/schema-constrained decoding: the output ALWAYS has the schema's
                 shape, but the VALUES can still be wrong (shape is not truth).
"""

from __future__ import annotations

import json
import random
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

TOOLS = {
    "get_weather": {"city": str, "units": ("c", "f")},  # tuple = enum of allowed values
    "add": {"a": int, "b": int},
}

TASKS = [
    {"id": "t1", "prompt": "Weather in Paris in celsius", "tool": "get_weather", "args": {"city": "Paris", "units": "c"}},
    {"id": "t2", "prompt": "Weather in Austin in fahrenheit", "tool": "get_weather", "args": {"city": "Austin", "units": "f"}},
    {"id": "t3", "prompt": "Add 17 and 25", "tool": "add", "args": {"a": 17, "b": 25}},
]

ALIASES = {"location": "city", "town": "city", "unit": "units", "x": "a", "y": "b"}


def _json(task: dict) -> str:
    return json.dumps({"tool": task["tool"], "args": task["args"]})


class SteadyModel:
    name = "steady-7b"

    def generate(self, task: dict, run: int, attempt: int = 0, feedback: str = "") -> str:
        return "Sure, here is the call:\n```json\n" + _json(task) + "\n```"


class FlakyModel:
    name = "flaky-3b"
    QUIRKS = [("clean", 45), ("single_quotes", 10), ("trailing_comma", 10), ("renamed_arg", 10),
              ("string_number", 8), ("extra_field", 7), ("no_json", 5), ("wrong_enum", 5)]

    def generate(self, task: dict, run: int, attempt: int = 0, feedback: str = "") -> str:
        rng = random.Random(f"{self.name}|{task['id']}|{run}|{attempt}")
        quirk = rng.choices([q for q, _ in self.QUIRKS], weights=[w for _, w in self.QUIRKS])[0]
        call = {"tool": task["tool"], "args": dict(task["args"])}
        if quirk == "single_quotes":
            return json.dumps(call).replace('"', "'")
        if quirk == "trailing_comma":
            return json.dumps(call)[:-1] + ",}"
        if quirk == "renamed_arg":
            key = next(iter(call["args"]))
            alias = next((a for a, real in ALIASES.items() if real == key), key)
            call["args"][alias] = call["args"].pop(key)
        elif quirk == "string_number":
            call["args"] = {k: (str(v) if isinstance(v, int) else v) for k, v in call["args"].items()}
        elif quirk == "extra_field":
            call["args"]["reason"] = "because"
        elif quirk == "no_json":
            return f"I would call {task['tool']} for you. Please confirm."
        elif quirk == "wrong_enum" and "units" in call["args"]:
            call["args"]["units"] = {"c": "celsius", "f": "fahrenheit"}[call["args"]["units"]]
        return json.dumps(call)


# ---------------------------------------------------------------- parsing and validation

def strict_parse(text: str) -> dict | None:
    """Pull the first {...} (fences and prose allowed) and parse it with a STRICT JSON parser."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def validate(call: dict | None) -> tuple[bool, str]:
    if call is None:
        return False, "no parseable JSON object"
    tool, args = call.get("tool"), call.get("args")
    if tool not in TOOLS:
        return False, f"unknown tool {tool!r}"
    schema = TOOLS[tool]
    if not isinstance(args, dict) or set(args) != set(schema):
        return False, f"arguments must be exactly {sorted(schema)}"
    for key, rule in schema.items():
        val = args[key]
        if isinstance(rule, tuple):
            if val not in rule:
                return False, f"{key} must be one of {list(rule)}"
        elif not isinstance(val, rule) or isinstance(val, bool):
            return False, f"{key} must be {rule.__name__}"
    return True, "ok"


def constrain(text: str, task_tool_hint: str | None = None) -> dict:
    """Simulate schema-constrained decoding: always return a call with exactly the schema's shape."""
    obj = strict_parse(text.replace("'", '"')) or {}
    tool = obj.get("tool") if obj.get("tool") in TOOLS else (task_tool_hint or "get_weather")
    raw = obj.get("args") if isinstance(obj.get("args"), dict) else {}
    raw = {ALIASES.get(k, k): v for k, v in raw.items()}
    out: dict = {}
    for key, rule in TOOLS[tool].items():
        val = raw.get(key)
        if isinstance(rule, tuple):
            val = val if val in rule else rule[0]  # forced into the enum, maybe the wrong member
        elif rule is int:
            try:
                val = int(val)
            except (TypeError, ValueError):
                val = 0
        else:
            val = val if isinstance(val, str) else ""
        out[key] = val
    return {"tool": tool, "args": out}


# ---------------------------------------------------------------- running and measuring

@dataclass
class Outcome:
    model: str
    task: str
    run: int
    parse_ok: bool
    schema_ok: bool
    correct: bool
    call: str  # canonical JSON of what was finally accepted ("" if nothing)
    attempts: int


def run_one(model, task: dict, run: int, mode: str, retries: int = 2) -> Outcome:
    expected = {"tool": task["tool"], "args": task["args"]}
    attempts, feedback, call, parse_ok = 0, "", None, False
    for attempt in range(retries + 1 if mode == "retry" else 1):
        attempts += 1
        text = model.generate(task, run, attempt, feedback)
        if mode == "constrained":
            call, parse_ok = constrain(text, task["tool"]), strict_parse(text.replace("'", '"')) is not None
            break
        parsed = strict_parse(text)
        parse_ok = parsed is not None
        ok, feedback = validate(parsed)
        if ok:
            call = parsed
            break
        call = None
    schema_ok = call is not None and validate(call)[0]
    correct = schema_ok and call == expected
    canon = json.dumps(call, sort_keys=True) if call is not None else ""
    return Outcome(model.name, task["id"], run, parse_ok, schema_ok, correct, canon, attempts)


def run_all(models, tasks, n_runs: int, mode: str, concurrent: bool = True) -> list[Outcome]:
    jobs = [(m, t, r) for m in models for t in tasks for r in range(n_runs)]
    if concurrent:
        with ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(lambda j: run_one(j[0], j[1], j[2], mode), jobs))  # keeps job order
    return [run_one(m, t, r, mode) for m, t, r in jobs]


def summarize(outcomes: list[Outcome]) -> dict[str, dict[str, float]]:
    report: dict[str, dict[str, float]] = {}
    for model in sorted({o.model for o in outcomes}):
        mine = [o for o in outcomes if o.model == model]
        consistency = []
        for task in sorted({o.task for o in mine}):
            calls = Counter(o.call for o in mine if o.task == task)
            consistency.append(calls.most_common(1)[0][1] / sum(calls.values()))
        n = len(mine)
        report[model] = {
            "parse_valid": sum(o.parse_ok for o in mine) / n,
            "schema_valid": sum(o.schema_ok for o in mine) / n,
            "correct": sum(o.correct for o in mine) / n,
            "consistency": sum(consistency) / len(consistency),
            "avg_attempts": sum(o.attempts for o in mine) / n,
        }
    return report
