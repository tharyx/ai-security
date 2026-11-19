"""Mini GitLab-CI-style runner that understands a pseudo `syft` command, produces an SBOM and archives it as an artifact.

Nothing real is executed: script lines are matched against a small set of simulated commands. The workspace is a dict.
"""

from __future__ import annotations

import json
import re
import shlex

import yaml

PIPELINE = """\
stages: [build, sbom, gate]
variables:
  SYFT_IMAGE: "registry.example/tools/syft:1.0.0"

build:
  stage: build
  script:
    - echo "building"

sbom:
  stage: sbom
  image: $SYFT_IMAGE
  script:
    - syft dir:. -o cyclonedx-json=sbom.cdx.json
  artifacts:
    paths: [sbom.cdx.json]
    expire_in: 90 days
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_COMMIT_TAG'

gate:
  stage: gate
  script:
    - sbom-check sbom.cdx.json --max-unpinned 0
"""

WORKSPACE = {"requirements.txt": "flask==3.0.3\nrequests==2.32.3\njinja2==3.1.4\n", "app.py": "print('hi')\n"}


def _parse_reqs(text):
    return [tuple(l.strip().split("==")) for l in text.splitlines() if "==" in l]


def _eval_rule(expr: str, variables: dict) -> bool:
    """Tiny evaluator for `$VAR == "x"`, `$VAR` truthiness and `||`."""
    for part in expr.split("||"):
        part = part.strip()
        m = re.fullmatch(r'\$(\w+)\s*==\s*"([^"]*)"', part)
        if m:
            if variables.get(m.group(1)) == m.group(2):
                return True
        elif part.startswith("$") and variables.get(part[1:]):
            return True
    return False


def _run_command(line: str, ws: dict, log: list):
    argv = shlex.split(line)
    cmd = argv[0]
    if cmd == "echo":
        log.append(" ".join(argv[1:]))
    elif cmd == "syft":
        target, out = argv[1], argv[argv.index("-o") + 1]
        fmt, _, path = out.partition("=")
        if fmt != "cyclonedx-json" or not target.startswith("dir:"):
            raise RuntimeError(f"simulated syft supports dir: and cyclonedx-json only, got {target} {fmt}")
        comps = [{"type": "library", "name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"} for n, v in _parse_reqs(ws.get("requirements.txt", ""))]
        ws[path] = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": comps}, indent=1)
        log.append(f"syft: cataloged {len(comps)} packages -> {path}")
    elif cmd == "sbom-check":
        doc = json.loads(ws[argv[1]])
        if not doc.get("components"):
            raise RuntimeError("SBOM has no components")
        log.append(f"sbom-check: {len(doc['components'])} components OK")
    else:
        raise RuntimeError(f"unknown command: {cmd}")


def run(pipeline_yaml: str, workspace: dict, variables: dict | None = None):
    """Run stages in order. Returns {jobs: {name: status}, artifacts: {path: text}, log: [...]}."""
    cfg = yaml.safe_load(pipeline_yaml)
    vars_ = {**cfg.get("variables", {}), **(variables or {})}
    ws = dict(workspace)
    artifacts, status, log = {}, {}, []
    jobs = {k: v for k, v in cfg.items() if isinstance(v, dict) and "script" in v}
    for stage in cfg["stages"]:
        for name, job in jobs.items():
            if job.get("stage") != stage:
                continue
            rules = job.get("rules")
            if rules and not any(_eval_rule(r["if"], vars_) for r in rules):
                status[name] = "skipped"
                continue
            try:
                for line in job["script"]:
                    _run_command(line, ws, log)
                status[name] = "success"
            except Exception as e:  # noqa: BLE001
                status[name] = "failed"
                log.append(f"{name}: {e}")
                return {"jobs": status, "artifacts": artifacts, "log": log}
            for p in job.get("artifacts", {}).get("paths", []):
                if p in ws:
                    artifacts[p] = ws[p]
    return {"jobs": status, "artifacts": artifacts, "log": log}


def lint_pipeline(pipeline_yaml: str):
    """Policy checks for an SBOM-producing pipeline."""
    cfg = yaml.safe_load(pipeline_yaml)
    findings = []
    sbom_jobs = [(n, j) for n, j in cfg.items() if isinstance(j, dict) and any("syft" in s or "cdxgen" in s for s in j.get("script", []))]
    if not sbom_jobs:
        return ["no job generates an SBOM"]
    for name, j in sbom_jobs:
        img = str(j.get("image", ""))
        resolved = img.replace("$SYFT_IMAGE", cfg.get("variables", {}).get("SYFT_IMAGE", ""))
        if not resolved or resolved.endswith(":latest") or ":" not in resolved:
            findings.append(f"{name}: tool image is not pinned to a version or digest")
        if not j.get("artifacts", {}).get("paths"):
            findings.append(f"{name}: SBOM is not archived as an artifact")
        elif "expire_in" not in j["artifacts"]:
            findings.append(f"{name}: SBOM artifact has no expire_in (decide a retention period)")
        if not j.get("rules"):
            findings.append(f"{name}: SBOM job has no rules (should run on default branch and tags)")
    return findings
