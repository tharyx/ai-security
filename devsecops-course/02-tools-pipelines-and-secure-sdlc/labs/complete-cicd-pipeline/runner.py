"""A self-contained, simulated CI runner: build -> SCA -> SAST -> DAST -> deploy.

Every "tool" is a small Python function that reads the fixture app and returns fake findings.
Nothing is installed, executed in a shell or sent over the network.
(For a richer GitLab-style runner with needs/rules/artifacts, see csse-course ch1 how-cicd-works.
This lab is deliberately independent of it.)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
HERE = Path(__file__).parent


def load_app(directory=None) -> dict:
    d = Path(directory) if directory else HERE / "fixtures" / "app"
    return {p.name: p.read_text(encoding="utf-8") for p in d.iterdir() if p.is_file()}


def load_advisories(path=None) -> list:
    return json.loads(Path(path or HERE / "fixtures" / "advisories.json").read_text(encoding="utf-8"))


def load_pipeline(path=None) -> dict:
    return yaml.safe_load(Path(path or HERE / "pipeline.yml").read_text(encoding="utf-8"))


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def finding(tool, rule, severity, title, where=""):
    return {"tool": tool, "rule": rule, "severity": severity, "title": title, "where": where}


# ------------------------------------------------------------------ fake tools


def tool_npm_build(ctx):
    pkg = json.loads(ctx["app"]["package.json"])
    ctx["workspace"]["dist/app.tar"] = f"{pkg['name']}-{pkg['version']}"
    return [], [f"npm ci (simulated) -> {len(pkg['dependencies'])} dependencies", "artifact dist/app.tar created"]


def tool_npm_audit(ctx):
    pkg = json.loads(ctx["app"]["package.json"])
    out = []
    for adv in ctx["advisories"]:
        have = pkg["dependencies"].get(adv["package"])
        if have and _ver(have) < _ver(adv["fixed_in"]):
            out.append(finding("npm-audit", adv["id"], adv["severity"],
                               f"{adv['package']}@{have}: {adv['title']} (fix: {adv['fixed_in']})", "package.json"))
    return out, [f"audited {len(pkg['dependencies'])} packages against {len(ctx['advisories'])} advisories"]


SAST_RULES = [
    ("js-eval", r"\beval\s*\(", "high", "Use of eval() on dynamic input (CWE-95)"),
    ("js-sql-concat", r"[\"']\s*(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\+", "high",
     "SQL built by string concatenation (CWE-89)"),
    ("js-weak-random", r"Math\.random\s*\(", "medium", "Math.random() is not a secure random source (CWE-338)"),
    ("js-hardcoded-pass", r"password\s*[:=]\s*[\"'][^\"']{4,}[\"']", "high", "Hard-coded password (CWE-798)"),
]


def tool_semgrep(ctx):
    out = []
    for name, text in ctx["app"].items():
        if not name.endswith(".js"):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for rule, rx, sev, title in SAST_RULES:
                if re.search(rx, line, re.I if rule == "js-sql-concat" else 0):
                    out.append(finding("semgrep", rule, sev, title, f"{name}:{lineno}"))
    return out, [f"scanned {sum(n.endswith('.js') for n in ctx['app'])} JS file(s) with {len(SAST_RULES)} rules"]


def tool_zap_baseline(ctx):
    if "dist/app.tar" not in ctx["workspace"]:
        raise RuntimeError("nothing to test: dist/app.tar missing (did build run?)")
    rt = json.loads(ctx["app"]["runtime.json"])
    out, headers = [], {k.lower() for k in rt["headers"]}
    if "content-security-policy" not in headers:
        out.append(finding("zap-baseline", "missing-csp", "medium", "Content-Security-Policy header not set", "/"))
    if "strict-transport-security" not in headers:
        out.append(finding("zap-baseline", "missing-hsts", "low", "HSTS header not set", "/"))
    if "server" in headers:
        out.append(finding("zap-baseline", "server-banner", "low", "Server header reveals the framework", "/"))
    for c in rt["cookies"]:
        if not c.get("httponly"):
            out.append(finding("zap-baseline", "cookie-httponly", "medium", f"Cookie {c['name']} lacks HttpOnly", "/"))
        if not c.get("secure"):
            out.append(finding("zap-baseline", "cookie-secure", "medium", f"Cookie {c['name']} lacks Secure", "/"))
    for p in rt["paths_exposed"]:
        if re.search(r"\.git|\.env|backup", p):
            out.append(finding("zap-baseline", "sensitive-path", "high", f"Sensitive path exposed: {p}", p))
    if _ver(rt["tls"]) < (1, 2):
        out.append(finding("zap-baseline", "weak-tls", "high", f"TLS {rt['tls']} is too old", "/"))
    return out, ["spider + passive scan of the test environment (simulated)"]


def tool_deploy(ctx):
    ctx["workspace"]["deployed"] = ctx["workspace"]["dist/app.tar"]
    return [], [f"deployed {ctx['workspace']['dist/app.tar']} to staging (simulated)"]


TOOLS = {"npm-build": tool_npm_build, "npm-audit": tool_npm_audit, "semgrep": tool_semgrep,
         "zap-baseline": tool_zap_baseline, "deploy": tool_deploy}


# ------------------------------------------------------------------ runner


@dataclass
class JobRun:
    name: str
    stage: str
    status: str  # success | failed | skipped | failed_allowed | excluded
    findings: list = field(default_factory=list)
    log: list = field(default_factory=list)
    reason: str = ""


@dataclass
class PipelineRun:
    status: str  # success | failed
    jobs: list
    workspace: dict

    def job(self, name):
        return next(j for j in self.jobs if j.name == name)

    @property
    def order(self):
        return [j.name for j in self.jobs if j.status in ("success", "failed", "failed_allowed")]


def run_pipeline(pipeline: dict, app: dict, advisories: list, branch: str = "main") -> PipelineRun:
    ctx = {"app": app, "advisories": advisories, "workspace": {}}
    runs, failed = [], False
    jobs = pipeline["jobs"]
    for stage in pipeline["stages"]:
        for name, job in jobs.items():
            if job["stage"] != stage:
                continue
            if job.get("only") and job["only"] != branch:
                runs.append(JobRun(name, stage, "excluded", reason=f"only: {job['only']}"))
                continue
            if failed:
                runs.append(JobRun(name, stage, "skipped", reason="an earlier stage failed"))
                continue
            tool = TOOLS[job["tool"]]
            try:
                found, log = tool(ctx)
            except RuntimeError as exc:
                runs.append(JobRun(name, stage, "failed", reason=str(exc)))
                failed = True
                continue
            limit = job.get("fail_on")
            blocking = [f for f in found if limit and RANK[f["severity"]] >= RANK[limit]]
            if blocking:
                status = "failed_allowed" if job.get("allow_failure") else "failed"
                failed = failed or status == "failed"
                runs.append(JobRun(name, stage, status, found, log, f"{len(blocking)} finding(s) >= {limit}"))
            else:
                runs.append(JobRun(name, stage, "success", found, log))
    return PipelineRun("failed" if failed else "success", runs, ctx["workspace"])
