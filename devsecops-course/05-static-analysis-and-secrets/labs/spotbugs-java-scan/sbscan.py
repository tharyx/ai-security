"""Parse, triage and gate a SpotBugs (+ find-sec-bugs) report. Works on XML and SARIF fixtures; needs no Java.

Pipeline: parse -> normalise -> filter (category, test code) -> map to CWE -> apply triage decisions
(with expiry) -> group -> gate on SpotBugs rank.
SpotBugs ranks: 1-4 scariest, 5-9 scary, 10-14 troubling, 15-20 of concern.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path

# SpotBugs XML has no CWE field; find-sec-bugs documents a CWE per pattern. A small subset, verify at source.
CWE_BY_TYPE = {
    "SQL_INJECTION_JDBC": 89, "XSS_SERVLET": 79, "PATH_TRAVERSAL_IN": 22, "COMMAND_INJECTION": 78,
    "HARD_CODE_PASSWORD": 259, "WEAK_MESSAGE_DIGEST_MD5": 327, "PREDICTABLE_RANDOM": 330,
}
CWE_NAME = {89: "SQL Injection", 79: "Cross-site Scripting", 22: "Path Traversal", 78: "OS Command Injection",
            259: "Hard-coded Password", 327: "Broken or Risky Crypto", 330: "Insufficiently Random Values"}


@dataclass
class Bug:
    type: str
    category: str
    rank: int
    cls: str
    method: str
    path: str
    line: int
    cwe: int | None = None
    status: str = "open"          # open | false_positive | accepted | expired-decision
    reason: str = ""

    @property
    def key(self) -> str:
        """Line-independent identity: survives code moving around, so decisions do not go stale."""
        return f"{self.type}|{self.cls}|{self.method}"


def parse_xml(path: Path) -> list[Bug]:
    bugs = []
    for bi in ET.parse(path).getroot().iter("BugInstance"):
        method = bi.find("Method")
        sl = bi.find("SourceLine")
        cls = bi.find("Class")
        bugs.append(Bug(bi.get("type"), bi.get("category", ""), int(bi.get("rank", "20")), cls.get("classname"),
                        method.get("name") if method is not None else "", sl.get("sourcepath"), int(sl.get("start")),
                        CWE_BY_TYPE.get(bi.get("type"))))
    return bugs


def parse_sarif(path: Path) -> list[Bug]:
    run = json.loads(Path(path).read_text(encoding="utf-8"))["runs"][0]
    rules = {r["id"]: r.get("properties", {}) for r in run["tool"]["driver"].get("rules", [])}
    bugs = []
    for r in run["results"]:
        props, rule = r.get("properties", {}), rules.get(r["ruleId"], {})
        cwe = None
        for tag in rule.get("tags", []):
            m = re.search(r"cwe-(\d+)$", tag)
            if m:
                cwe = int(m.group(1))
        loc = r["locations"][0]["physicalLocation"]
        bugs.append(Bug(r["ruleId"], rule.get("category", ""), int(props.get("rank", 20)), props.get("class", ""),
                        props.get("method", ""), loc["artifactLocation"]["uri"], loc["region"]["startLine"], cwe))
    return bugs


def parse(path: Path) -> list[Bug]:
    return parse_sarif(path) if str(path).endswith(".sarif") else parse_xml(path)


def triage(bugs: list[Bug], config: dict, today: date):
    """Return (active, dropped) where dropped is a list of (bug, why)."""
    active, dropped = [], []
    decisions = config.get("decisions", {})
    for b in bugs:
        if any(x in b.path for x in config.get("exclude_paths", [])):
            dropped.append((b, "excluded path (test or generated code)"))
            continue
        if b.category not in config.get("include_categories", [b.category]):
            dropped.append((b, f"category {b.category} is not in scope for the security gate"))
            continue
        d = decisions.get(b.key)
        if d:
            if date.fromisoformat(d["expires"]) < today:
                b.status, b.reason = "expired-decision", f"{d['status']} decision expired {d['expires']}; re-review"
                active.append(b)
            else:
                b.status, b.reason = d["status"], d["reason"]
                dropped.append((b, f"{d['status']}: {d['reason']}"))
            continue
        active.append(b)
    return sorted(active, key=lambda x: (x.rank, x.type)), dropped


def group_by_cwe(bugs: list[Bug]) -> dict[str, list[Bug]]:
    out = defaultdict(list)
    for b in bugs:
        out[f"CWE-{b.cwe} {CWE_NAME.get(b.cwe, '')}".strip() if b.cwe else "no CWE"].append(b)
    return dict(out)


def gate(active: list[Bug], max_rank: int = 9) -> int:
    """Fail the build when any active bug is 'scary' or worse (rank <= max_rank)."""
    return 1 if any(b.rank <= max_rank for b in active) else 0


def label(rank: int) -> str:
    return "scariest" if rank <= 4 else "scary" if rank <= 9 else "troubling" if rank <= 14 else "of concern"
