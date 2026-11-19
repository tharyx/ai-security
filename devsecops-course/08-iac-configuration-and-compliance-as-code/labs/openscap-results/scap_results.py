"""Parse an XCCDF/ARF-like OpenSCAP results file into a compliance score (teaching tool, offline).

Reads the same structure `oscap xccdf eval --results-arf arf.xml` writes (simplified): a Benchmark with
Rule definitions and a TestResult with one rule-result per rule. It does not run OpenSCAP.

Scoring (a simplification of the XCCDF 1.2 "default" model; verify against the spec):
  pass, fixed                      -> counted as success
  fail, error, unknown             -> counted as failure
  notapplicable, notchecked,
  notselected, informational       -> excluded from the score
We also compute a severity-weighted score (high 3, medium 2, low 1) because ten failed "low" rules
and one failed "high" rule are not the same risk.

XML safety: result files can come from machines you do not control. We refuse any DOCTYPE
(blocks entity-expansion tricks) and, for real untrusted input, you should use defusedxml.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
import xml.etree.ElementTree as ET

SUCCESS = {"pass", "fixed"}
FAILURE = {"fail", "error", "unknown"}
EXCLUDED = {"notapplicable", "notchecked", "notselected", "informational"}
SEV_WEIGHT = {"high": 3.0, "medium": 2.0, "low": 1.0, "unknown": 1.0}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "unknown": 3}


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@dataclass
class RuleResult:
    rule_id: str
    short: str
    title: str
    severity: str
    result: str


@dataclass
class ScanResult:
    target: str
    profile: str
    declared_score: float | None
    rules: list[RuleResult] = field(default_factory=list)


def parse_results(source: str | Path | bytes) -> ScanResult:
    data = source if isinstance(source, bytes) else (Path(source).read_bytes() if not str(source).lstrip().startswith("<") else str(source).encode())
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DOCTYPE/ENTITY declarations are not accepted in result files")
    root = ET.fromstring(data)
    titles: dict[str, str] = {}
    for el in root.iter():
        if local(el.tag) == "Rule":
            title_el = next((c for c in el if local(c.tag) == "title"), None)
            titles[el.get("id", "")] = (title_el.text or "") if title_el is not None else ""
    test_result = next((el for el in root.iter() if local(el.tag) == "TestResult"), None)
    if test_result is None:
        raise ValueError("no TestResult element found")
    target = next((c.text or "" for c in test_result if local(c.tag) == "target"), "")
    profile = next((c.get("idref", "") for c in test_result if local(c.tag) == "profile"), "")
    score_el = next((c for c in test_result if local(c.tag) == "score"), None)
    declared = float(score_el.text) if score_el is not None and score_el.text else None
    out = ScanResult(target, profile, declared)
    for rr in (c for c in test_result if local(c.tag) == "rule-result"):
        rid = rr.get("idref", "")
        res = next((c.text or "" for c in rr if local(c.tag) == "result"), "unknown").strip()
        out.rules.append(RuleResult(rid, rid.split("rule_", 1)[-1], titles.get(rid, ""), rr.get("severity", "unknown"), res))
    return out


def score(scan: ScanResult) -> dict:
    counts = Counter(r.result for r in scan.rules)
    ok = sum(counts[k] for k in SUCCESS)
    bad = sum(counts[k] for k in FAILURE)
    flat = round(100.0 * ok / (ok + bad), 2) if ok + bad else 100.0
    num = sum(SEV_WEIGHT[r.severity] for r in scan.rules if r.result in SUCCESS)
    den = sum(SEV_WEIGHT[r.severity] for r in scan.rules if r.result in SUCCESS | FAILURE)
    weighted = round(100.0 * num / den, 2) if den else 100.0
    by_sev = Counter(r.severity for r in scan.rules if r.result in FAILURE)
    return {"counts": dict(counts), "flat_score": flat, "severity_weighted_score": weighted,
            "failed_by_severity": dict(by_sev), "declared_score": scan.declared_score,
            "matches_declared": scan.declared_score is None or abs(scan.declared_score - flat) < 0.01}


def failing(scan: ScanResult) -> list[RuleResult]:
    return sorted((r for r in scan.rules if r.result in FAILURE), key=lambda r: (SEV_ORDER[r.severity], r.short))


def compare(before: ScanResult, after: ScanResult) -> dict:
    b = {r.rule_id: r.result for r in before.rules}
    a = {r.rule_id: r.result for r in after.rules}
    improved = sorted(k.split("rule_", 1)[-1] for k in b if b[k] in FAILURE and a.get(k) in SUCCESS)
    regressed = sorted(k.split("rule_", 1)[-1] for k in b if b[k] in SUCCESS and a.get(k) in FAILURE)
    still = sorted(k.split("rule_", 1)[-1] for k in b if b[k] in FAILURE and a.get(k) in FAILURE)
    return {"improved": improved, "regressed": regressed, "still_failing": still,
            "delta_flat": round(score(after)["flat_score"] - score(before)["flat_score"], 2)}


def render(scan: ScanResult) -> str:
    s = score(scan)
    lines = [f"Target {scan.target}  profile {scan.profile.rsplit('profile_', 1)[-1]}",
             f"results: {s['counts']}",
             f"flat score {s['flat_score']}%  severity-weighted {s['severity_weighted_score']}%  (declared {s['declared_score']}, match {s['matches_declared']})",
             f"failed by severity: {s['failed_by_severity']}", "Failing rules, worst first:"]
    lines += [f"  [{r.severity:6}] {r.result:5} {r.short}: {r.title}" for r in failing(scan)]
    return "\n".join(lines)
