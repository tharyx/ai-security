"""Security gates over real report formats: SCA (OSV-scanner-like JSON), SAST (SARIF 2.1.0)
and DAST (ZAP traditional JSON report), with a suppression baseline that expires.

Report shapes follow the real tools but are simplified (verify field names against your tool
version). All package names and advisory ids are FICTIONAL (EXAMPLE-2026-NNNN).

`embed_in_pipeline()` loads the runner from the sibling simple-cicd-pipeline lab and registers
`sca-scan`, `sast-scan` and `dast-scan` actions, so the gates run as real pipeline jobs.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    tool: str
    id: str
    severity: str
    title: str
    where: str
    fixable: bool = False
    kev: bool = False

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.tool}|{self.id}|{self.where}".encode()).hexdigest()[:12]


# ------------------------------------------------------------------ parsers
def parse_sca(report: dict, kev: set[str] | None = None) -> list[Finding]:
    kev = kev or set()
    out = []
    for res in report.get("results", []):
        for pkg in res.get("packages", []):
            p = pkg["package"]
            for v in pkg.get("vulnerabilities", []):
                sev = v.get("database_specific", {}).get("severity", "MEDIUM").upper()
                fixed = any(e.get("fixed") for a in v.get("affected", []) for r in a.get("ranges", []) for e in r.get("events", []))
                ids = {v["id"], *v.get("aliases", [])}
                out.append(Finding("sca", v["id"], sev, v.get("summary", ""), f"{p['name']}@{p['version']}",
                                   fixable=fixed, kev=bool(ids & kev)))
    return out


def parse_sarif(sarif: dict) -> list[Finding]:
    out = []
    for run in sarif.get("runs", []):
        rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for res in run.get("results", []):
            rule = rules.get(res["ruleId"], {})
            score = rule.get("properties", {}).get("security-severity")
            if score is not None:  # GitHub code scanning convention: CVSS-like 0.0-10.0
                s = float(score)
                sev = "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW"
            else:  # fall back to the SARIF result level
                sev = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(res.get("level", "warning"), "MEDIUM")
            loc = res["locations"][0]["physicalLocation"]
            out.append(Finding("sast", res["ruleId"], sev, res["message"]["text"],
                               f"{loc['artifactLocation']['uri']}:{loc.get('region', {}).get('startLine', 0)}"))
    return out


def parse_zap(report: dict) -> list[Finding]:
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    out = []
    for site in report.get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances", [{}])[0]
            out.append(Finding("dast", str(a["pluginid"]), risk[str(a["riskcode"])], a["alert"],
                               f"{inst.get('method', 'GET')} {inst.get('uri', site.get('@name', ''))}"))
    return out


# ------------------------------------------------------------------ policy and baseline
DEFAULT_POLICY = {
    "sca": {"fail_on": "HIGH", "also_fail_on_kev": True, "only_fixable": True},
    "sast": {"fail_on": "HIGH"},
    "dast": {"fail_on": "HIGH"},
}


def active_suppressions(baseline: list[dict], today: dt.date) -> dict[str, dict]:
    return {s["fingerprint"]: s for s in baseline
            if s.get("reason") and s.get("owner") and dt.date.fromisoformat(s["expires"]) >= today}


def evaluate(findings: list[Finding], policy: dict | None = None, baseline: list[dict] | None = None,
             today: dt.date | None = None) -> tuple[int, list[str]]:
    """Return (exit_code, report lines). Suppressions need a reason, an owner and a future expiry."""
    policy = policy or DEFAULT_POLICY
    supp = active_suppressions(baseline or [], today or dt.date(2026, 11, 19))
    lines, failing = [], 0
    for f in sorted(findings, key=lambda x: (-SEV_RANK[x.severity], x.tool, x.id)):
        p = policy[f.tool]
        breaking = SEV_RANK[f.severity] >= SEV_RANK[p["fail_on"]]
        if f.tool == "sca" and p.get("only_fixable") and not f.fixable:
            breaking = False
        if f.tool == "sca" and p.get("also_fail_on_kev") and f.kev:
            breaking = True
        tag = "FAIL" if breaking else "warn"
        if breaking and f.fingerprint in supp:
            s = supp[f.fingerprint]
            tag = f"suppressed until {s['expires']} ({s['owner']}: {s['reason']})"
            breaking = False
        failing += breaking
        extra = (" KEV" if f.kev else "") + (" fix-available" if f.fixable else "")
        lines.append(f"[{tag}] {f.tool.upper()} {f.severity} {f.id} {f.title} @ {f.where}{extra} #{f.fingerprint}")
    return (1 if failing else 0), lines


# ------------------------------------------------------------------ pipeline integration
def load_runner():
    path = HERE.parent / "simple-cicd-pipeline" / "pipeline.py"
    name = "aps16_pipeline_runner_for_gates"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def embed_in_pipeline(report_dir: Path, baseline: list[dict] | None = None, kev: set[str] | None = None):
    runner = load_runner()

    def make(tool: str, filename: str, parser):
        def act(ctx) -> int:
            data = json.loads((report_dir / filename).read_text(encoding="utf-8"))
            findings = parser(data, kev) if tool == "sca" else parser(data)
            code, lines = evaluate(findings, baseline=baseline)
            for line in lines:
                ctx.log(line)
            out = ctx.workspace / f"gl-{tool}-report.json"
            out.write_text(json.dumps([f.__dict__ for f in findings]), encoding="utf-8")
            return code
        return act

    runner.ACTIONS["sca-scan"] = make("sca", "sca-osv.json", parse_sca)
    runner.ACTIONS["sast-scan"] = make("sast", "sast.sarif", parse_sarif)
    runner.ACTIONS["dast-scan"] = make("dast", "zap-report.json", parse_zap)
    runner.ACTIONS["deploy-staging"] = lambda ctx: (ctx.log("deployed to staging (simulated)"), 0)[1]
    return runner
