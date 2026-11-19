"""Managing threat models after the workshop: documentation, backlog, bugs and tickets, code, automation.

* fingerprint(): a stable id for a threat (component + STRIDE + normalised title), so re-running the
  model does not create duplicate tickets
* naive_sync() vs sync(): the naive version creates a ticket on every run (duplicates, noise);
  the managed version is an idempotent upsert that also detects drift between model and tracker
* ticket type: a design gap becomes a Story, a vulnerability found in code becomes a Bug,
  an accepted risk becomes a Risk acceptance (needs owner and expiry)
* code links: mitigated threats must point at code or tests that exist
* to_markdown(): the living document is generated, never hand-edited
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import date
from pathlib import Path


def load(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def normalise(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()


def fingerprint(t: dict) -> str:
    raw = f"{t['component']}|{t['stride']}|{normalise(t['title'])}"
    return "TM-" + hashlib.sha1(raw.encode()).hexdigest()[:10]


def ticket_type(t: dict) -> str:
    if t["status"] == "accepted":
        return "Risk acceptance"
    return "Bug" if t.get("kind") == "vulnerability" else "Story"


def dedupe(threats: list[dict]) -> list[dict]:
    """Merge threats that differ only in punctuation or case of the title (same fingerprint)."""
    seen: dict[str, dict] = {}
    for t in threats:
        fp = fingerprint(t)
        if fp not in seen:
            seen[fp] = t
        elif _sev(t) < _sev(seen[fp]):  # keep the higher severity
            seen[fp] = t
    return list(seen.values())


def _sev(t: dict) -> int:
    return {"High": 0, "Medium": 1, "Low": 2}.get(t.get("severity"), 3)


def naive_sync(threats: list[dict], tracker: list[dict]) -> list[dict]:
    """What many teams do first: export every open threat as a new ticket on every run."""
    tracker = copy.deepcopy(tracker)
    for t in threats:
        if t["status"] == "open":
            tracker.append({"key": f"SEC-{len(tracker) + 1}", "summary": t["title"], "state": "To Do"})
    return tracker


def sync(threats: list[dict], tracker: dict[str, dict], today: date) -> tuple[dict[str, dict], list[str]]:
    """Idempotent upsert keyed by fingerprint. Returns (tracker, findings for humans)."""
    tracker = copy.deepcopy(tracker)
    notes = []
    for t in dedupe(threats):
        fp = fingerprint(t)
        tk = tracker.get(fp)
        if t["status"] in ("open", "accepted") and tk is None:
            tracker[fp] = {"type": ticket_type(t), "summary": f"[{t['stride']}] {t['component']}: {t['title']}",
                           "severity": t["severity"], "state": "To Do", "owner": t.get("owner", "")}
            notes.append(f"created {ticket_type(t)} {fp}")
            tk = tracker[fp]
        elif tk is not None and tk["severity"] != t["severity"]:
            tk["severity"] = t["severity"]
            notes.append(f"updated severity of {fp} to {t['severity']}")
        if tk is None:
            continue
        if t["status"] == "open" and tk["state"] == "Done":
            tk["state"] = "Reopened"
            notes.append(f"REOPENED {fp}: ticket closed but the model still shows the threat open (verify the fix)")
        if t["status"] == "mitigated" and tk["state"] != "Done":
            notes.append(f"DRIFT {fp}: model says mitigated but ticket is {tk['state']}")
        if t["status"] == "accepted":
            exp = t.get("accept_expires")
            if not t.get("owner") or not exp:
                notes.append(f"INVALID acceptance {fp}: needs owner and expiry")
            elif date.fromisoformat(exp) < today:
                notes.append(f"EXPIRED acceptance {fp}: review the risk again")
    return tracker, notes


def check_code_links(threats: list[dict], repo_files: set[str]) -> list[str]:
    """Mitigated threats must name the code or test that implements the mitigation, and it must exist."""
    problems = []
    for t in threats:
        if t["status"] != "mitigated":
            continue
        refs = t.get("code_refs", [])
        if not refs:
            problems.append(f"{t['id']}: mitigated but no code or test reference")
        for r in refs:
            if r.split("::")[0] not in repo_files:
                problems.append(f"{t['id']}: reference {r} does not exist (renamed or deleted?)")
    return problems


def to_markdown(model_name: str, threats: list[dict]) -> str:
    rows = [f"| {fingerprint(t)} | {t['component']} | {t['stride']} | {t['title']} | {t['severity']} | {t['status']} |"
            for t in sorted(dedupe(threats), key=lambda t: (_sev(t), t["component"]))]
    counts = {s: sum(t["status"] == s for t in dedupe(threats)) for s in ("open", "mitigated", "accepted")}
    return "\n".join([f"# Threat model: {model_name}", "",
                      f"Open {counts['open']}, mitigated {counts['mitigated']}, accepted {counts['accepted']}.", "",
                      "| Id | Component | STRIDE | Threat | Severity | Status |", "|---|---|---|---|---|---|", *rows])


def ci_gate(threats: list[dict], notes: list[str], code_problems: list[str]) -> int:
    """Automation: fail on an open High threat, a reopened ticket, an expired/invalid acceptance or a broken link."""
    if any(t["status"] == "open" and t["severity"] == "High" for t in dedupe(threats)):
        return 1
    if any(n.startswith(("REOPENED", "EXPIRED", "INVALID")) for n in notes) or code_problems:
        return 1
    return 0
