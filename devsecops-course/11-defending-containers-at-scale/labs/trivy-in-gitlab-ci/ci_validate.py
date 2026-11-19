"""Validate a .gitlab-ci.yml for a trustworthy Trivy job (offline, YAML parse only)."""
from __future__ import annotations

import re

import yaml


def jobs(doc: dict) -> dict[str, dict]:
    reserved = {"stages", "variables", "default", "include", "workflow", "image", "cache"}
    return {k: v for k, v in doc.items() if k not in reserved and isinstance(v, dict)}


def validate(text: str) -> list[str]:
    doc = yaml.safe_load(text)
    problems: list[str] = []
    stages = doc.get("stages", [])
    scan_jobs = {n: j for n, j in jobs(doc).items()
                 if any("trivy" in str(s) for s in j.get("script", []))}
    if not scan_jobs:
        return ["no job runs trivy"]
    for name, j in scan_jobs.items():
        img = j.get("image")
        img = img.get("name") if isinstance(img, dict) else img
        variables = doc.get("variables", {})
        img = re.sub(r"\$(\w+)", lambda m: str(variables.get(m.group(1), m.group(0))), str(img or ""))
        script = " ".join(j.get("script", []))
        if not img:
            problems.append(f"{name}: no image set")
        elif img.endswith(":latest") or ":" not in img:
            problems.append(f"{name}: image {img} is not pinned (latest)")
        if "--exit-code 1" not in script and "--exit-code=1" not in script:
            problems.append(f"{name}: no --exit-code 1, so findings never fail the job")
        if "--severity" not in script:
            problems.append(f"{name}: no --severity threshold")
        if "|| true" in script:
            problems.append(f"{name}: '|| true' swallows the exit code")
        if j.get("allow_failure") is True:
            problems.append(f"{name}: allow_failure: true makes the gate advisory")
        art = j.get("artifacts") or {}
        if not art.get("paths") and not art.get("reports"):
            problems.append(f"{name}: no artifacts, nobody can read the report")
        elif art.get("when") != "always":
            problems.append(f"{name}: artifacts.when should be always (report is needed most on failure)")
        if j.get("stage") not in stages:
            problems.append(f"{name}: stage {j.get('stage')} is not declared")
    later = [n for n, j in jobs(doc).items() if "release" in n or j.get("stage") == "release"]
    for n in later:
        if not any(s in jobs(doc)[n].get("needs", []) for s in scan_jobs):
            problems.append(f"{n}: release job does not need the scan job")
    return problems
