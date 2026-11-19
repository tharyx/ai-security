"""Conflict triage for security champions: a small, testable exercise.

Three tools:
  1. `classify_mode(text)`: which Thomas-Kilmann mode is a person USING in a scenario?
     (competing, collaborating, compromising, avoiding, accommodating), from cue phrases.
  2. `glasl_stage(text)`: roughly where is the conflict on Glasl's 9-stage escalation model,
     grouped into three levels (win-win 1-3, win-lose 4-6, lose-lose 7-9)?
  3. `recommend_mode(stakes, relationship, urgency)`: which mode should the champion CHOOSE?

Plus prioritisation helpers for conflicting priorities: RICE and a simple risk score.

The keyword heuristics are a deliberately simple "baseline bot". The real exercise is
`score_answers()`: you write your own answers in a JSON file and compare them with the answer key,
reading the explanation for each scenario. Models are simplifications; see the lesson for limits.
"""
from __future__ import annotations

import json
from pathlib import Path

MODES = ("competing", "collaborating", "compromising", "avoiding", "accommodating")
LEVELS = {1: "win-win", 2: "win-win", 3: "win-win", 4: "win-lose", 5: "win-lose", 6: "win-lose",
          7: "lose-lose", 8: "lose-lose", 9: "lose-lose"}

MODE_CUES = {
    "competing": ["insists", "insisted", "overrule", "my way", "non-negotiable", "escalated straight to", "orders the team",
                  "refuses to discuss", "blocks the release", "ultimatum"],
    "collaborating": ["both", "together", "joint", "workshop", "root cause", "explore options", "shared goal",
                      "pair", "co-design"],
    "compromising": ["split", "halfway", "middle", "meet in the middle", "trade", "partial", "for now, and"],
    "avoiding": ["ignores", "postpones", "skips the meeting", "no reply", "not my problem", "stays silent", "later",
                 "changes the subject"],
    "accommodating": ["gives in", "lets them", "agrees to drop", "to keep the peace", "whatever you prefer", "goes along", "go along"],
}

STAGE_CUES = [  # checked from the most escalated down; first match wins
    (9, ["together into the abyss", "destroy both", "whatever it costs us"]),
    (8, ["fragment", "cut off their", "sabotage"]),
    (7, ["limited destruction", "delete their", "retaliate"]),
    (6, ["ultimatum", "or else", "threat"]),
    (5, ["loss of face", "publicly humiliate", "public blame", "all-hands blame"]),
    (4, ["coalition", "recruit allies", "taking sides", "lobbying"]),
    (3, ["actions not words", "fait accompli", "went ahead without", "deeds, not words"]),
    (2, ["debate", "polarised", "polarized", "point-scoring", "talking past"]),
    (1, ["tension", "hardening", "friction", "irritation", "disagree"]),
]


def classify_mode(text: str) -> str | None:
    t = text.lower()
    scores = {m: sum(c in t for c in cues) for m, cues in MODE_CUES.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] else None


def glasl_stage(text: str) -> int | None:
    t = text.lower()
    for stage, cues in STAGE_CUES:
        if any(c in t for c in cues):
            return stage
    return None


def recommend_mode(stakes: str, relationship: str, urgency: str) -> str:
    """stakes/relationship/urgency: 'low' | 'high'. Based on Thomas-Kilmann guidance (simplified):
    - an urgent, high-stakes security issue (active incident, critical exposure): competing (decide, then repair)
    - high stakes, important relationship, time available: collaborating
    - moderate/time-boxed: compromising as a temporary settlement
    - low stakes, important relationship: accommodating (build goodwill)
    - low stakes, low relationship value or bad timing: avoiding (for now)"""
    if stakes == "high" and urgency == "high":
        return "competing"
    if stakes == "high":
        return "collaborating"
    if relationship == "high" and urgency == "high":
        return "compromising"
    if relationship == "high":
        return "accommodating"
    return "avoiding"


# ------------------------------------------------------------------ prioritisation for conflicting priorities
def rice(reach: float, impact: float, confidence: float, effort: float) -> float:
    """RICE = Reach x Impact x Confidence / Effort (Intercom's product-prioritisation formula)."""
    if effort <= 0:
        raise ValueError("effort must be positive")
    return round(reach * impact * confidence / effort, 2)


def risk_score(likelihood: int, impact: int, internet_exposed: bool, known_exploited: bool) -> int:
    """1-5 x 1-5, raised for exposure and active exploitation; used to rank security work."""
    score = likelihood * impact
    if internet_exposed:
        score += 5
    if known_exploited:
        score += 10
    return score


def moscow(items: list[dict]) -> dict[str, list[str]]:
    """Bucket items by explicit flags: must (legal/regulatory or critical risk), should, could, wont."""
    out = {"must": [], "should": [], "could": [], "wont": []}
    for it in items:
        if it.get("regulatory") or it.get("risk", 0) >= 20:
            out["must"].append(it["name"])
        elif it.get("risk", 0) >= 10:
            out["should"].append(it["name"])
        elif it.get("value", 0) > 0:
            out["could"].append(it["name"])
        else:
            out["wont"].append(it["name"])
    return out


# ------------------------------------------------------------------ the exercise
def load(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def score_answers(answers: dict, key: dict) -> tuple[int, int, list[str]]:
    """Compare your answers {id: {"mode_used", "stage", "recommended"}} with the key.
    Returns (points, max_points, feedback lines)."""
    points, total, fb = 0, 0, []
    for sid, k in key.items():
        a = answers.get(sid, {})
        for field in ("mode_used", "stage", "recommended"):
            total += 1
            ok = a.get(field) == k[field] or (field == "stage" and isinstance(a.get(field), int)
                                               and abs(a[field] - k[field]) <= 1)
            points += ok
            if not ok:
                fb.append(f"{sid} {field}: you said {a.get(field)!r}, key says {k[field]!r}. {k['why']}")
    return points, total, fb


def validate_key(key: dict) -> list[str]:
    errs = []
    for sid, k in key.items():
        if k["mode_used"] not in MODES or k["recommended"] not in MODES:
            errs.append(f"{sid}: unknown mode")
        if k["stage"] not in LEVELS:
            errs.append(f"{sid}: stage must be 1-9")
        if not k.get("why"):
            errs.append(f"{sid}: missing explanation")
    return errs
