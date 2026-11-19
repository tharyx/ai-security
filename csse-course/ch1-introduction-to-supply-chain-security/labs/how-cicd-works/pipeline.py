"""A tiny, offline simulator for a .gitlab-ci.yml-style pipeline.

It reads stages, jobs, script, needs, rules, artifacts, allow_failure and when.
NOTHING is executed in a shell. Every script line is either:
  echo TEXT          -> recorded (with $VARIABLES expanded)
  write PATH TEXT    -> creates a virtual file in the job workspace
  require PATH       -> fails the job if the file is missing from the workspace
  exit N             -> exits with code N (non-zero fails the job)
  call NAME          -> runs a Python callable from the `actions` dict
  anything else      -> recorded as "(simulated) ..." and ignored
Educational model only: real GitLab behaviour has many more details. Verify at docs.gitlab.com.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

RESERVED = {"stages", "variables", "default", "workflow", "include", "image", "before_script", "after_script"}
DEFAULT_STAGES = [".pre", "build", "test", "deploy", ".post"]


class PipelineError(ValueError):
    """The YAML is not a valid pipeline (unknown stage, bad needs, cycle...)."""


@dataclass
class Job:
    name: str
    stage: str
    script: list
    needs: list | None
    rules: list | None
    artifacts: list
    allow_failure: bool
    when: str
    dependencies: list | None
    order: int


@dataclass
class JobResult:
    name: str
    stage: str
    status: str  # success | failed | failed_allowed | skipped | manual | excluded
    reason: str = ""
    round: int | None = None
    log: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    status: str  # success | failed | blocked
    jobs: dict
    order: list  # names of jobs that actually ran, in execution order

    def status_of(self, name):
        return self.jobs[name].status


def parse_pipeline(text: str):
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise PipelineError("pipeline must be a mapping")
    stages = list(data.get("stages") or DEFAULT_STAGES)
    base_vars = {str(k): str(v) for k, v in (data.get("variables") or {}).items()}
    jobs = {}
    for i, (name, body) in enumerate(k for k in data.items() if k[0] not in RESERVED):
        if not isinstance(body, dict):
            raise PipelineError(f"job {name!r} must be a mapping")
        stage = body.get("stage", "test")
        if stage not in stages:
            raise PipelineError(f"job {name!r} uses unknown stage {stage!r}")
        script = body.get("script")
        if not script:
            raise PipelineError(f"job {name!r} has no script")
        needs = body.get("needs")
        if needs is not None:
            needs = [n["job"] if isinstance(n, dict) else n for n in needs]
        art = (body.get("artifacts") or {}).get("paths", [])
        jobs[name] = Job(name, stage, [script] if isinstance(script, str) else list(script), needs,
                         body.get("rules"), list(art), bool(body.get("allow_failure", False)),
                         body.get("when", "on_success"), body.get("dependencies"), i)
    idx = {s: i for i, s in enumerate(stages)}
    for j in jobs.values():
        for n in j.needs or []:
            if n not in jobs:
                raise PipelineError(f"job {j.name!r} needs unknown job {n!r}")
            if idx[jobs[n].stage] > idx[j.stage]:
                raise PipelineError(f"job {j.name!r} needs {n!r} which is in a later stage")
    _check_cycles(jobs)
    return stages, base_vars, jobs


def _check_cycles(jobs):
    state = {}

    def visit(n):
        if state.get(n) == 1:
            raise PipelineError(f"needs cycle through {n!r}")
        if state.get(n) == 2:
            return
        state[n] = 1
        for m in jobs[n].needs or []:
            visit(m)
        state[n] = 2

    for n in jobs:
        visit(n)


def eval_rule_if(expr: str, variables: dict) -> bool:
    """Supports: $VAR, $VAR == "x", $VAR != "x", joined with && and ||. No parentheses."""
    def atom(a: str) -> bool:
        a = a.strip()
        m = re.fullmatch(r'\$(\w+)\s*(==|!=)\s*"([^"]*)"', a)
        if m:
            v = variables.get(m.group(1), "")
            return (v == m.group(3)) if m.group(2) == "==" else (v != m.group(3))
        m = re.fullmatch(r"\$(\w+)", a)
        if m:
            return bool(variables.get(m.group(1)))
        raise PipelineError(f"unsupported rule expression: {a!r}")

    return any(all(atom(a) for a in part.split("&&")) for part in expr.split("||"))


def decide(job: Job, variables: dict):
    """Return (included, when). First matching rule wins; no rules = always included."""
    if job.rules is None:
        return job.when != "never", job.when
    for r in job.rules:
        cond = r.get("if")
        if cond is None or eval_rule_if(cond, variables):
            w = r.get("when", "on_success")
            return w != "never", w
    return False, "never"


def _run_script(job, workspace, variables, actions):
    log = []
    for line in job.script:
        line = str(line)
        for k, v in variables.items():
            line = line.replace("$" + k, v)
        cmd, _, rest = line.partition(" ")
        if cmd == "echo":
            log.append(rest)
        elif cmd == "write":
            path, _, text = rest.partition(" ")
            workspace[path] = text
            log.append(f"wrote {path}")
        elif cmd == "require":
            if rest not in workspace:
                log.append(f"ERROR: missing {rest}")
                return False, log
            log.append(f"found {rest}")
        elif cmd == "exit":
            code = int(rest or 0)
            log.append(f"exit {code}")
            if code:
                return False, log
        elif cmd == "call":
            fn = (actions or {}).get(rest)
            if fn is None:
                log.append(f"ERROR: no action {rest!r}")
                return False, log
            try:
                ok = fn(workspace)
            except Exception as exc:  # a failing callable fails the job
                log.append(f"ERROR: {exc}")
                return False, log
            log.append(f"called {rest}")
            if ok is False:
                return False, log
        else:
            log.append(f"(simulated) {line}")
    return True, log


def run_pipeline(text: str, variables: dict | None = None, actions: dict | None = None,
                 approved: set | None = None) -> PipelineResult:
    stages, base_vars, jobs = parse_pipeline(text)
    variables = {**base_vars, **(variables or {})}
    approved = approved or set()
    sidx = {s: i for i, s in enumerate(stages)}
    results = {}
    active = {}
    for n, j in jobs.items():
        inc, when = decide(j, variables)
        if inc:
            active[n] = (j, when)
        else:
            results[n] = JobResult(n, j.stage, "excluded", "rules did not match")
    done, order, rnd = {}, [], 0
    store = {}  # job name -> artifacts of a successful job
    blocked = False
    pending = dict(active)

    def ok_for_dependents(d):
        r = done[d]
        if r.status == "success" or r.status == "failed_allowed":
            return True
        return r.status == "manual" and jobs[d].allow_failure

    while pending:
        rnd += 1
        ready = []
        for n, (j, _when) in pending.items():
            if j.needs is not None:
                waits = [d for d in j.needs if d in active]
            else:
                waits = [m for m, (k, _) in active.items() if sidx[k.stage] < sidx[j.stage]]
            if all(d in done for d in waits):
                ready.append(n)
        if not ready:
            break
        ready.sort(key=lambda n: (sidx[jobs[n].stage], jobs[n].order))
        for n in ready:
            j, when = pending.pop(n)
            res = JobResult(n, j.stage, "success", round=rnd)
            results[n] = res
            done[n] = res
            if j.needs is not None:
                deps = [d for d in j.needs if d in active]
            else:
                deps = [m for m in active if sidx[jobs[m].stage] < sidx[j.stage]]
            if j.dependencies is not None:
                deps = [d for d in j.dependencies if d in active]
            bad = [d for d in deps if not ok_for_dependents(d)]
            if bad:
                res.status, res.reason = "skipped", f"dependency not successful: {bad[0]}"
                continue
            if when == "manual" and n not in approved:
                res.status, res.reason = "manual", "waiting for a person to play it"
                if not j.allow_failure:
                    blocked = True
                continue
            ws = {}
            for d in deps:
                ws.update(store.get(d, {}))
            ok, log = _run_script(j, ws, variables, actions)
            res.log = log
            order.append(n)
            if ok:
                saved = {p: ws[p] for p in j.artifacts if p in ws}
                store[n] = saved
                res.artifacts = saved
            elif j.allow_failure:
                res.status, res.reason = "failed_allowed", "failure allowed"
            else:
                res.status = "failed"
    for n, (j, _) in pending.items():
        results[n] = JobResult(n, j.stage, "skipped", "an earlier job did not succeed")
    statuses = {r.status for r in results.values()}
    status = "failed" if "failed" in statuses else ("blocked" if blocked else "success")
    return PipelineResult(status, results, order)
