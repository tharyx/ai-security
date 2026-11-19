"""A tiny CI/CD runner that behaves like GitLab CI in the ways that matter for security.

A pipeline definition (JSON, shaped like a simplified .gitlab-ci.yml) has:
  stages:     ordered list
  variables:  {NAME: {"value": ..., "masked": bool, "protected": bool}}
  jobs:       {name: {stage, script: [action names], needs: [jobs], artifacts: [paths],
                      allow_failure: bool, when: on_success|manual|always, only_branches: [..]}}

"script" steps are names of Python actions registered in `ACTIONS` (no shell is ever run).
An action gets a JobContext (workspace dir, visible variables, artifacts from `needs`) and returns
an exit code; it writes log lines with ctx.log(). The runner:
  * validates the definition (unknown stage, unknown need, need in a later stage, cycles),
  * runs stages in order and skips later stages after a failure (unless allow_failure),
  * passes artifacts only along declared `needs` and records a sha256 digest for each,
  * never runs `when: manual` jobs without an approval,
  * applies branch rules, exposes protected variables only on protected branches,
  * masks masked variable values in job logs.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


class PipelineError(Exception):
    pass


@dataclass
class JobContext:
    name: str
    workspace: Path
    variables: dict[str, str]
    inputs: dict[str, Path]  # artifact path -> file, from needed jobs
    lines: list[str] = field(default_factory=list)

    def log(self, msg: str) -> None:
        self.lines.append(msg)


Action = Callable[[JobContext], int]
ACTIONS: dict[str, Action] = {}


def action(name: str):
    def deco(fn: Action) -> Action:
        ACTIONS[name] = fn
        return fn
    return deco


# ------------------------------------------------------------------ built-in demo actions
@action("compile")
def _compile(ctx: JobContext) -> int:
    out = ctx.workspace / "dist" / "orders-api.tar"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"orders-api build {ctx.variables.get('CI_COMMIT_SHA', 'local')}", encoding="utf-8")
    ctx.log("built dist/orders-api.tar")
    return 0


@action("unit-tests")
def _unit_tests(ctx: JobContext) -> int:
    ok = ctx.variables.get("SIMULATE_TEST_FAILURE") != "1"
    ctx.log("42 passed" if ok else "1 failed: test_orders_owner_check")
    return 0 if ok else 1


@action("lint")
def _lint(ctx: JobContext) -> int:
    ctx.log("3 style warnings")
    return 1  # always "fails"; the job is allow_failure in the fixture


@action("package-image")
def _package(ctx: JobContext) -> int:
    src = ctx.inputs.get("dist/orders-api.tar")
    if not src:
        ctx.log("ERROR: build artifact missing (did you declare needs?)")
        return 1
    ctx.log(f"image built from artifact sha256:{hashlib.sha256(src.read_bytes()).hexdigest()[:12]}")
    return 0


@action("deploy")
def _deploy(ctx: JobContext) -> int:
    token = ctx.variables.get("DEPLOY_TOKEN")
    if not token:
        ctx.log("ERROR: DEPLOY_TOKEN not available on this branch")
        return 1
    ctx.log(f"deploying with token {token}")  # careless log line: masking must hide the value
    return 0


# ------------------------------------------------------------------ definition handling
def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate(defn: dict) -> list[str]:
    errs = []
    stages = defn.get("stages", [])
    jobs = defn.get("jobs", {})
    for name, j in jobs.items():
        if j.get("stage") not in stages:
            errs.append(f"{name}: unknown stage {j.get('stage')!r}")
        for n in j.get("needs", []):
            if n not in jobs:
                errs.append(f"{name}: needs unknown job {n!r}")
            elif j.get("stage") in stages and jobs[n].get("stage") in stages and \
                    stages.index(jobs[n]["stage"]) > stages.index(j["stage"]):
                errs.append(f"{name}: needs {n!r} from a later stage")
        for step in j.get("script", []):
            if step not in ACTIONS:
                errs.append(f"{name}: unknown script step {step!r}")
    seen, stack = set(), set()

    def visit(n: str) -> None:
        if n in stack:
            errs.append(f"cycle in needs at {n!r}")
            return
        if n in seen or n not in jobs:
            return
        stack.add(n)
        for m in jobs[n].get("needs", []):
            visit(m)
        stack.discard(n)
        seen.add(n)

    for n in jobs:
        visit(n)
    return errs


@dataclass
class JobResult:
    name: str
    stage: str
    status: str  # success, failed, failed (allowed), skipped, manual, not-run (rules)
    log: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)  # path -> sha256


@dataclass
class PipelineResult:
    status: str
    jobs: dict[str, JobResult]

    def summary(self) -> str:
        rows = [f"{j.stage:10} {j.name:20} {j.status}" for j in self.jobs.values()]
        return "\n".join(rows + [f"pipeline: {self.status}"])


def _mask(text: str, secrets_: list[str]) -> str:
    for s in secrets_:
        if s:
            text = text.replace(s, "[MASKED]")
    return text


def run(defn: dict, branch: str = "main", protected_branches: tuple[str, ...] = ("main",),
        approvals: set[str] | None = None, extra_vars: dict[str, str] | None = None) -> PipelineResult:
    errs = validate(defn)
    if errs:
        raise PipelineError("; ".join(errs))
    approvals = approvals or set()
    protected = branch in protected_branches
    variables: dict[str, str] = {"CI_COMMIT_BRANCH": branch, "CI_COMMIT_SHA": "0f1e2d3c"}
    masked: list[str] = []
    for k, v in defn.get("variables", {}).items():
        if v.get("protected") and not protected:
            continue
        variables[k] = v["value"]
        if v.get("masked"):
            masked.append(v["value"])
    variables.update(extra_vars or {})

    root = Path(tempfile.mkdtemp(prefix="aps16-pipeline-"))
    results: dict[str, JobResult] = {}
    produced: dict[str, dict[str, Path]] = {}
    blocked = False
    try:
        for stage in defn["stages"]:
            for name, j in defn["jobs"].items():
                if j["stage"] != stage:
                    continue
                if j.get("only_branches") and branch not in j["only_branches"]:
                    results[name] = JobResult(name, stage, "not-run (rules)")
                    continue
                when = j.get("when", "on_success")
                if blocked and when != "always":
                    results[name] = JobResult(name, stage, "skipped")
                    continue
                if when == "manual" and name not in approvals:
                    results[name] = JobResult(name, stage, "manual")
                    continue
                if any(results.get(n) and results[n].status not in ("success", "failed (allowed)") for n in j.get("needs", [])):
                    results[name] = JobResult(name, stage, "skipped")
                    continue
                ws = root / name
                ws.mkdir()
                inputs = {p: f for n in j.get("needs", []) for p, f in produced.get(n, {}).items()}
                ctx = JobContext(name, ws, dict(variables), inputs)
                code = 0
                for step in j.get("script", []):
                    code = ACTIONS[step](ctx)
                    if code:
                        break
                res = JobResult(name, stage, "success" if code == 0 else
                                ("failed (allowed)" if j.get("allow_failure") else "failed"),
                                [_mask(line, masked) for line in ctx.lines])
                if code == 0:
                    produced[name] = {}
                    for p in j.get("artifacts", []):
                        f = ws / p
                        if f.exists():
                            produced[name][p] = f
                            res.artifacts[p] = hashlib.sha256(f.read_bytes()).hexdigest()
                results[name] = res
            if any(r.status == "failed" for r in results.values() if r.stage == stage):
                blocked = True
        status = "failed" if any(r.status == "failed" for r in results.values()) else (
            "blocked (manual)" if any(r.status == "manual" for r in results.values()) else "passed")
        return PipelineResult(status, results)
    finally:
        shutil.rmtree(root, ignore_errors=True)
