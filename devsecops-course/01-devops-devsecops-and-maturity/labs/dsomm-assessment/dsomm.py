"""DSOMM-like self-assessment: level per dimension, gaps to the next level, a roadmap.

Rule (strict, like a maturity model): a dimension is at level N when EVERY activity of
levels 1..N is implemented. A single missing level-2 activity keeps you at level 1, even
if you already do level-3 things. Those are reported as "ahead of level".
"partial" does not count unless partial_credit=True.
This is a teaching model with a simplified activity list; use dsomm.owasp.org for the real one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

VALID = {"implemented", "partial", "not-started"}


class AssessmentError(ValueError):
    pass


def load_yaml(source: str):
    """Accept a YAML text (contains a newline) or a file path."""
    if "\n" in source:
        return yaml.safe_load(source)
    with open(source, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@dataclass
class DimensionResult:
    key: str
    title: str
    level: int
    next_level: int | None
    gaps: list  # unsatisfied activities of the next level
    ahead: list  # satisfied activities above the next level (done early)
    coverage: dict  # level -> (done, total)


@dataclass
class Assessment:
    dimensions: dict
    overall: int  # weakest dimension
    average: float
    max_level: int = 4
    unknown: list = field(default_factory=list)


def _status_ok(status: str, partial_credit: bool) -> bool:
    return status == "implemented" or (partial_credit and status == "partial")


def assess(catalog: dict, answers: dict, partial_credit: bool = False) -> Assessment:
    given = dict(answers.get("activities") or {})
    known = {a["id"] for d in catalog["dimensions"].values() for a in d["activities"]}
    unknown = sorted(set(given) - known)
    if unknown:
        raise AssessmentError(f"unknown activity ids (typo?): {', '.join(unknown)}")
    for aid, st in given.items():
        if st not in VALID:
            raise AssessmentError(f"{aid}: status must be one of {sorted(VALID)}, got {st!r}")
    top = catalog.get("levels", 4)
    results = {}
    for key, dim in catalog["dimensions"].items():
        acts = dim["activities"]
        ok = {a["id"]: _status_ok(given.get(a["id"], "not-started"), partial_credit) for a in acts}
        coverage = {}
        for lv in range(1, top + 1):
            at = [a for a in acts if a["level"] == lv]
            coverage[lv] = (sum(ok[a["id"]] for a in at), len(at))
        level = 0
        for lv in range(1, top + 1):
            if all(ok[a["id"]] for a in acts if a["level"] <= lv):
                level = lv
            else:
                break
        nxt = level + 1 if level < top else None
        gaps = [a for a in acts if nxt and a["level"] == nxt and not ok[a["id"]]]
        ahead = [a for a in acts if nxt and a["level"] > nxt and ok[a["id"]]]
        results[key] = DimensionResult(key, dim["title"], level, nxt, gaps, ahead, coverage)
    levels = [r.level for r in results.values()]
    return Assessment(results, min(levels), round(sum(levels) / len(levels), 2), top)


def roadmap(catalog: dict, answers: dict, target: int | None = None, partial_credit: bool = False) -> list:
    """Ordered to-do list to reach `target` in every dimension (default: overall level + 1).

    Lowest level first, then cheapest effort; ties broken by id so the output is stable.
    """
    a = assess(catalog, answers, partial_credit)
    target = target or min(a.overall + 1, a.max_level)
    given = answers.get("activities") or {}
    steps = []
    for key, dim in catalog["dimensions"].items():
        for act in dim["activities"]:
            if act["level"] <= target and not _status_ok(given.get(act["id"], "not-started"), partial_credit):
                steps.append({"dimension": key, "id": act["id"], "level": act["level"],
                              "effort": act["effort"], "title": act["title"],
                              "status": given.get(act["id"], "not-started")})
    steps.sort(key=lambda s: (s["level"], s["effort"], s["id"]))
    for i, s in enumerate(steps, 1):
        s["order"] = i
    return steps


def render_report(catalog: dict, answers: dict, target: int | None = None) -> str:
    a = assess(catalog, answers)
    lines = [f"Team: {answers.get('team', '?')}", ""]
    lines.append(f"{'Dimension':<28} Level  Next-level gaps")
    for r in a.dimensions.values():
        gaps = ", ".join(g["id"] for g in r.gaps) or "-"
        lines.append(f"{r.title:<28} L{r.level}     {gaps}")
    lines += ["", f"Overall (weakest dimension): L{a.overall}   average: {a.average}"]
    steps = roadmap(catalog, answers, target)
    goal = target or min(a.overall + 1, a.max_level)
    lines += ["", f"Roadmap to L{goal} in every dimension ({len(steps)} activities):"]
    for s in steps:
        lines.append(f"  {s['order']:>2}. [L{s['level']} effort {s['effort']}] {s['id']:<28} {s['status']}")
    return "\n".join(lines)
