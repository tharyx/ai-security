"""Security in an agile backlog: security user stories, abuse cases, Definition of Ready/Done
checks, Scrum-event security activities and Gherkin generation from abuse cases.

Backlog format (JSON): {"stories": [...], "abuse_cases": [...], "sprint": {...}}
  story:      id, text ("As a <role>, I want <goal> so that <benefit>"), tags, acceptance_criteria,
              status (todo/doing/done). Security criteria start with "SEC:".
  abuse case: id, text ("As an attacker, I want ... so that ..."), threatens (story id), stride,
              mitigated_by (story id or null), given, when, then (the expected DEFENSE).
  sprint:     planned (story ids), threat_modeled_at_planning (story ids), retro_actions (list)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

STORY = re.compile(r"^As an? (?P<role>.+?), I want (?P<goal>.+?),? so that (?P<benefit>.+?)\.?$", re.IGNORECASE)
SENSITIVE_TAGS = {"auth", "pii", "payment", "admin", "upload", "export", "secrets"}
SENSITIVE_WORDS = re.compile(r"\b(log ?in|password|reset|pay|card|upload|admin|export|personal|token)\b", re.I)
ATTACKER_ROLES = re.compile(r"\b(attacker|fraudster|malicious|insider|bot)\b", re.I)
STRIDE = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service",
          "Elevation of Privilege"}

# 2020 Scrum Guide: the Sprint contains Sprint Planning, Daily Scrum, Sprint Review, Sprint Retrospective.
# Backlog refinement is an ongoing activity, not an event.
SCRUM_SECURITY = {
    "Sprint": "Security work is part of the Sprint Goal and the Definition of Done, not a separate phase.",
    "Sprint Planning": "Threat model each security-relevant story (what can go wrong?) and add abuse cases "
                       "and SEC: acceptance criteria before it is pulled in.",
    "Daily Scrum": "Raise security blockers early (a new data flow, a secret needed, a failing security test).",
    "Sprint Review": "Demo the security acceptance criteria and show the security test results to stakeholders.",
    "Sprint Retrospective": "Review security findings and escaped defects; turn them into process actions.",
    "Backlog refinement (activity)": "Write security stories and abuse cases; size security work with the team.",
}


@dataclass
class Parsed:
    role: str
    goal: str
    benefit: str


def parse_story(text: str) -> Parsed | None:
    m = STORY.match(text.strip())
    return Parsed(m["role"], m["goal"], m["benefit"]) if m else None


def is_security_relevant(story: dict) -> bool:
    return bool(SENSITIVE_TAGS & set(story.get("tags", []))) or bool(SENSITIVE_WORDS.search(story["text"]))


def security_criteria(story: dict) -> list[str]:
    return [c for c in story.get("acceptance_criteria", []) if c.startswith("SEC:")]


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def check_backlog(backlog: dict) -> list[str]:
    """Return problems. An empty list means the backlog meets the security Definition of Ready/Done."""
    problems = []
    stories = {s["id"]: s for s in backlog["stories"]}
    abuse = backlog.get("abuse_cases", [])
    for s in backlog["stories"]:
        if not parse_story(s["text"]):
            problems.append(f"{s['id']}: not in 'As a <role>, I want <goal> so that <benefit>' form")
        if not is_security_relevant(s):
            continue
        if not any(a["threatens"] == s["id"] for a in abuse):
            problems.append(f"{s['id']}: security-relevant story has no abuse case (Definition of Ready)")
        if not security_criteria(s):
            problems.append(f"{s['id']}: security-relevant story has no SEC: acceptance criterion")
    for a in abuse:
        p = parse_story(a["text"])
        if not p or not ATTACKER_ROLES.search(p.role):
            problems.append(f"{a['id']}: abuse case must be written from an attacker's point of view")
        if a.get("stride") not in STRIDE:
            problems.append(f"{a['id']}: unknown STRIDE category {a.get('stride')!r}")
        if a["threatens"] not in stories:
            problems.append(f"{a['id']}: threatens unknown story {a['threatens']}")
        m = a.get("mitigated_by")
        if not m:
            problems.append(f"{a['id']}: abuse case has no mitigating story")
        elif m not in stories:
            problems.append(f"{a['id']}: mitigated_by unknown story {m}")
        if not all(a.get(k) for k in ("given", "when", "then")):
            problems.append(f"{a['id']}: abuse case cannot become a test (needs given/when/then)")
    sprint = backlog.get("sprint", {})
    for sid in sprint.get("planned", []):
        if sid in stories and is_security_relevant(stories[sid]) and sid not in sprint.get("threat_modeled_at_planning", []):
            problems.append(f"{sid}: pulled into the Sprint without threat modeling at Sprint Planning")
    for s in backlog["stories"]:
        if s.get("status") == "done" and is_security_relevant(s) and not s.get("security_tests_passed"):
            problems.append(f"{s['id']}: marked done but security tests have not passed (Definition of Done)")
    return problems


def to_gherkin(backlog: dict) -> str:
    """Turn abuse cases into executable Gherkin scenarios (run them with pytest-bdd/behave)."""
    lines = ["Feature: Abuse cases from the threat model", ""]
    for a in backlog.get("abuse_cases", []):
        if not all(a.get(k) for k in ("given", "when", "then")):
            continue
        lines += [f"  @threat-{a['id']} @{a['stride'].lower().replace(' ', '-')}",
                  f"  Scenario: {a['id']} is blocked ({a['threatens']})",
                  f"    Given {a['given']}", f"    When {a['when']}", f"    Then {a['then']}", ""]
    return "\n".join(lines).rstrip() + "\n"


def gate(backlog: dict) -> int:
    return 1 if check_backlog(backlog) else 0
