"""A tiny Gherkin parser and step runner in pure Python (no behave, no pytest-bdd).

Supported Gherkin subset: Feature, Background, Scenario, Scenario Outline + Examples table,
Given/When/Then/And/But, comments (#) and @tags. Not supported: doc strings, step tables,
Rule:, localisation. This is a teaching runner. For real projects use behave or pytest-bdd.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

KEYWORDS = ("Given", "When", "Then", "And", "But")


class GherkinError(ValueError):
    pass


@dataclass
class Scenario:
    name: str
    steps: list
    tags: list = field(default_factory=list)
    outline_row: dict | None = None


@dataclass
class Feature:
    name: str
    tags: list
    background: list
    scenarios: list


def _cells(line: str) -> list:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def parse(text: str) -> Feature:
    name, ftags, background, scenarios = None, [], [], []
    pending_tags: list = []
    mode = None              # "background" | "scenario" | "examples"
    cur = None               # current scenario dict
    examples: list = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@"):
            pending_tags += [t for t in line.split() if t.startswith("@")]
            continue
        if line.startswith("Feature:"):
            name, ftags, pending_tags = line[len("Feature:"):].strip(), pending_tags, []
            continue
        if line.startswith("Background:"):
            mode = "background"
            continue
        m = re.match(r"(Scenario Outline|Scenario):\s*(.*)", line)
        if m:
            cur = {"name": m.group(2), "outline": m.group(1) == "Scenario Outline",
                   "steps": [], "tags": pending_tags, "examples": []}
            pending_tags = []
            scenarios.append(cur)
            mode = "scenario"
            continue
        if line.startswith("Examples:"):
            if not cur or not cur["outline"]:
                raise GherkinError("Examples: is only allowed under a Scenario Outline")
            mode, examples = "examples", []
            continue
        if line.startswith("|"):
            if mode != "examples":
                raise GherkinError(f"unexpected table row: {line}")
            examples.append(_cells(line))
            if len(examples) > 1:
                cur["examples"] = [dict(zip(examples[0], row)) for row in examples[1:]]
            continue
        kw = line.split(" ", 1)[0]
        if kw in KEYWORDS:
            step = (kw, line.split(" ", 1)[1].strip() if " " in line else "")
            if mode == "background":
                background.append(step)
            elif cur is not None and mode == "scenario":
                cur["steps"].append(step)
            else:
                raise GherkinError(f"step outside a scenario: {line}")
            continue
        if cur is None and mode is None:
            continue  # free-text description under "Feature:"
        raise GherkinError(f"cannot parse line: {line}")
    if name is None:
        raise GherkinError("no Feature: line")
    out = []
    for sc in scenarios:
        if not sc["steps"]:
            raise GherkinError(f"scenario '{sc['name']}' has no steps")
        if sc["outline"]:
            if not sc["examples"]:
                raise GherkinError(f"outline '{sc['name']}' has no Examples")
            for row in sc["examples"]:
                steps = [(k, re.sub(r"<(\w[\w-]*)>", lambda m: row[m.group(1)], t)) for k, t in sc["steps"]]
                out.append(Scenario(f"{sc['name']} [{', '.join(row.values())}]", steps, sc["tags"], row))
        else:
            out.append(Scenario(sc["name"], sc["steps"], sc["tags"]))
    return Feature(name, ftags, background, out)


class StepRegistry:
    """Maps step text (regex, full match) to a Python function: fn(ctx, *groups)."""

    def __init__(self):
        self._steps = []

    def step(self, pattern: str):
        rx = re.compile(pattern)

        def deco(fn):
            self._steps.append((rx, fn))
            return fn
        return deco

    def find(self, text: str):
        for rx, fn in self._steps:
            m = rx.fullmatch(text)
            if m:
                return fn, m.groups()
        return None, ()


@dataclass
class StepResult:
    keyword: str
    text: str
    status: str  # passed | failed | undefined | skipped
    error: str = ""


@dataclass
class ScenarioResult:
    name: str
    status: str  # passed | failed | undefined
    steps: list
    tags: list


@dataclass
class FeatureResult:
    name: str
    scenarios: list

    @property
    def passed(self) -> bool:
        return all(s.status == "passed" for s in self.scenarios)

    def failed(self) -> list:
        return [s for s in self.scenarios if s.status != "passed"]


class Context:
    """Per-scenario scratch space; steps store state as attributes."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def run_feature(feature: Feature, registry: StepRegistry, make_context) -> FeatureResult:
    results = []
    for sc in feature.scenarios:
        ctx = make_context()
        steps_out, status, failed = [], "passed", False
        for kw, text in feature.background + sc.steps:
            if failed:
                steps_out.append(StepResult(kw, text, "skipped"))
                continue
            fn, groups = registry.find(text)
            if fn is None:
                steps_out.append(StepResult(kw, text, "undefined"))
                status, failed = "undefined", True
                continue
            try:
                fn(ctx, *groups)
                steps_out.append(StepResult(kw, text, "passed"))
            except AssertionError as exc:
                steps_out.append(StepResult(kw, text, "failed", str(exc)))
                status, failed = "failed", True
        results.append(ScenarioResult(sc.name, status, steps_out, feature.tags + sc.tags))
    return FeatureResult(feature.name, results)


def run_text(text: str, registry: StepRegistry, make_context) -> FeatureResult:
    return run_feature(parse(text), registry, make_context)
