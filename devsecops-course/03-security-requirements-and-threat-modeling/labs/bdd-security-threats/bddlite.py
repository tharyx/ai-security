"""A tiny Gherkin runner for security scenarios (about 150 lines, standard library only).

Supports: Feature, Background, Scenario, Scenario Outline + Examples tables, tags, and the
step keywords Given/When/Then/And/But. Step definitions are regexes registered with @step.
This is a teaching twin of BDD-Security / behave / pytest-bdd, not a replacement for them.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

STEPS: list[tuple[re.Pattern, object]] = []


def step(pattern: str):
    def deco(fn):
        STEPS.append((re.compile(f"^{pattern}$"), fn))
        return fn
    return deco


@dataclass
class Scenario:
    name: str
    tags: list[str]
    steps: list[str]
    feature: str = ""


@dataclass
class Outcome:
    scenario: str
    status: str            # passed | failed | skipped | undefined
    message: str = ""


@dataclass
class Feature:
    name: str = ""
    tags: list[str] = field(default_factory=list)
    background: list[str] = field(default_factory=list)
    scenarios: list[Scenario] = field(default_factory=list)


KEYWORDS = ("Given", "When", "Then", "And", "But")


def parse(text: str) -> Feature:
    feat = Feature()
    pending_tags: list[str] = []
    cur: dict | None = None      # {"kind", "name", "tags", "steps", "examples"}
    blocks: list[dict] = []
    in_examples = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@"):
            pending_tags += line.split()
            continue
        if line.startswith("Feature:"):
            feat.name, feat.tags, pending_tags = line[8:].strip(), pending_tags, []
        elif line.startswith("Background:"):
            cur = {"kind": "background", "name": "", "tags": [], "steps": [], "examples": []}
            blocks.append(cur)
            in_examples = False
        elif line.startswith(("Scenario Outline:", "Scenario:")):
            kind = "outline" if line.startswith("Scenario Outline:") else "scenario"
            cur = {"kind": kind, "name": line.split(":", 1)[1].strip(), "tags": feat.tags + pending_tags,
                   "steps": [], "examples": []}
            pending_tags = []
            blocks.append(cur)
            in_examples = False
        elif line.startswith("Examples:"):
            in_examples = True
        elif line.startswith("|") and cur is not None and in_examples:
            cur["examples"].append([c.strip() for c in line.strip("|").split("|")])
        elif line.startswith(KEYWORDS) and cur is not None:
            cur["steps"].append(line.split(" ", 1)[1].strip())
        elif cur is None:
            continue          # free-text description under Feature:
    for b in blocks:
        if b["kind"] == "background":
            feat.background = b["steps"]
        elif b["kind"] == "scenario":
            feat.scenarios.append(Scenario(b["name"], b["tags"], b["steps"], feat.name))
        else:
            header, *rows = b["examples"]
            for row in rows:
                vals = dict(zip(header, row))
                steps = [re.sub(r"<(\w+)>", lambda m: vals[m.group(1)], s) for s in b["steps"]]
                feat.scenarios.append(Scenario(f"{b['name']} [{', '.join(row)}]", b["tags"], steps, feat.name))
    return feat


def _run_step(text: str, ctx: dict) -> None:
    for pat, fn in STEPS:
        m = pat.match(text)
        if m:
            fn(ctx, *m.groups())
            return
    raise LookupError(f"undefined step: {text}")


def run_feature(feat: Feature, make_context, skip_tags=("@wip",)) -> list[Outcome]:
    out = []
    for sc in feat.scenarios:
        if any(t in sc.tags for t in skip_tags):
            out.append(Outcome(sc.name, "skipped", "tag " + ",".join(t for t in sc.tags if t in skip_tags)))
            continue
        ctx = make_context()
        try:
            for s in feat.background + sc.steps:
                _run_step(s, ctx)
            out.append(Outcome(sc.name, "passed"))
        except LookupError as e:
            out.append(Outcome(sc.name, "undefined", str(e)))
        except AssertionError as e:
            out.append(Outcome(sc.name, "failed", str(e)))
    return out


def run_dir(features_dir: Path, make_context, skip_tags=("@wip",)) -> list[Outcome]:
    outcomes = []
    for p in sorted(Path(features_dir).glob("*.feature")):
        outcomes += run_feature(parse(p.read_text(encoding="utf-8")), make_context, skip_tags)
    return outcomes


def exit_code(outcomes: list[Outcome]) -> int:
    return 1 if any(o.status in ("failed", "undefined") for o in outcomes) else 0


def main(argv=None) -> int:      # pragma: no cover - thin CLI
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    import steps
    import app_sim
    STEPS.clear()
    steps.register(step)
    vulnerable = "--vulnerable" in (argv or sys.argv[1:])
    outs = run_dir(here / "features", lambda: {"app": app_sim.App(vulnerable=vulnerable)})
    for o in outs:
        print(f"{o.status.upper():9} {o.scenario}" + (f"  -> {o.message}" if o.message else ""))
    return exit_code(outs)
