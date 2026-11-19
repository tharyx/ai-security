"""Check a .gitlab-ci.yml-style file against the four stage exercises.

Usage:  python stage_checker.py starter.gitlab-ci.yml
Pure static analysis of YAML. Nothing is executed.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

RESERVED = {"stages", "variables", "default", "workflow", "include", "image", "before_script", "after_script"}
SECRET_NAME = re.compile(r"(token|secret|password|passwd|api[_-]?key|private[_-]?key)", re.I)
SCAN_WORDS = ("sast", "secret", "scan", "dependency", "trivy", "gitleaks", "semgrep")


@dataclass
class Check:
    id: str
    ok: bool
    message: str


def load(text: str):
    data = yaml.safe_load(text) or {}
    stages = list(data.get("stages") or ["build", "test", "deploy"])
    jobs = {k: v for k, v in data.items() if k not in RESERVED and isinstance(v, dict)}
    return data, stages, jobs


def _stage_of(job):
    return job.get("stage", "test")


def check_test_stage(data, stages, jobs):
    if "test" not in stages:
        return Check("EX1", False, "no 'test' stage in stages:")
    if "build" in stages and stages.index("test") < stages.index("build"):
        return Check("EX1", False, "'test' must come after 'build'")
    if "deploy" in stages and stages.index("test") > stages.index("deploy"):
        return Check("EX1", False, "'test' must come before 'deploy'")
    if not [j for j in jobs.values() if _stage_of(j) == "test"]:
        return Check("EX1", False, "the 'test' stage has no job")
    return Check("EX1", True, "test stage exists, in order, with a job")


def check_security_stage(data, stages, jobs):
    sec = [s for s in stages if s in ("security", "scan", "sast")]
    if not sec:
        return Check("EX2", False, "no security stage (security, scan or sast)")
    s = sec[0]
    if "deploy" in stages and stages.index(s) > stages.index("deploy"):
        return Check("EX2", False, "the security stage must run before deploy")
    scans = [n for n, j in jobs.items() if _stage_of(j) == s and any(w in n.lower() for w in SCAN_WORDS)]
    if not scans:
        return Check("EX2", False, "the security stage needs a scan job (name it e.g. sast or secret-scan)")
    return Check("EX2", True, f"security stage before deploy with scan job(s): {', '.join(scans)}")


def _manual_on_main(job):
    rules = job.get("rules")
    if rules:
        for r in rules:
            cond = str(r.get("if", ""))
            if r.get("when") == "manual" and "main" in cond and "==" in cond:
                return True
        return False
    return False


def check_manual_gate(data, stages, jobs):
    prod = [j for n, j in jobs.items() if "prod" in n.lower() and _stage_of(j) == "deploy"]
    if not prod:
        return Check("EX3", False, "no deploy job with 'prod' in its name")
    for j in prod:
        if not _manual_on_main(j):
            return Check("EX3", False, "prod deploy must have a rule: if $CI_COMMIT_BRANCH == \"main\" with when: manual")
    return Check("EX3", True, "prod deploy is manual and limited to main")


def check_no_secrets(data, stages, jobs):
    bad = []
    for k, v in (data.get("variables") or {}).items():
        val = v.get("value") if isinstance(v, dict) else v
        if SECRET_NAME.search(str(k)) and val not in (None, ""):
            bad.append(k)
    for n, j in jobs.items():
        for k, v in (j.get("variables") or {}).items():
            if SECRET_NAME.search(str(k)) and v not in (None, ""):
                bad.append(f"{n}.{k}")
    if bad:
        return Check("EX4", False, f"secret-looking values in YAML: {', '.join(bad)} (use masked, protected CI/CD variables)")
    return Check("EX4", True, "no secret values in the YAML")


def check_all(text: str):
    data, stages, jobs = load(text)
    problems = [c for c in (f(data, stages, jobs) for f in (
        check_test_stage, check_security_stage, check_manual_gate, check_no_secrets))]
    return problems


def stage_order(text: str):
    """Return {stage: [jobs]} in stage order: the table GitLab draws as columns."""
    _, stages, jobs = load(text)
    return {s: [n for n, j in jobs.items() if _stage_of(j) == s] for s in stages}


if __name__ == "__main__":
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("starter.gitlab-ci.yml")
    results = check_all(src.read_text())
    for c in results:
        print(f"{'PASS' if c.ok else 'FAIL'}  {c.id}  {c.message}")
    print("stages:", stage_order(src.read_text()))
    sys.exit(0 if all(c.ok for c in results) else 1)
