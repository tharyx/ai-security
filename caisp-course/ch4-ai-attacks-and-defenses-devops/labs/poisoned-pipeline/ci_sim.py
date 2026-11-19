"""A SIMULATED CI runner, to teach Poisoned Pipeline Execution (PPE, OWASP CICD-SEC-4).

Nothing real runs. Workflow files are parsed as YAML, but ``run:`` lines go to a tiny fake shell
that understands only a few commands (``make``, ``bash file``, ``python file``, ``pytest``, ``echo``)
plus one attacker command, ``exfil NAME host``, which just APPENDS the value to ``network_log``.
The "secret" is a canary made by ``make_canary()``. So you can see what a hostile PR could steal
without any exploit code.

PPE in two forms:
  DIRECT    the PR edits the pipeline definition itself (.github/workflows/*.yml)
  INDIRECT  the PR edits a file the unchanged pipeline runs (Makefile, scripts/, conftest.py, ...)

Rules copied from GitHub Actions behavior (verify details in the GitHub docs):
  pull_request         the workflow file comes from the PR merge result (the PR can change it);
                       repository secrets are NOT given to workflows triggered from forks
  pull_request_target  the workflow file comes from the BASE branch, secrets ARE available, and
                       the token is write-capable. If the job then checks out the PR head, the
                       PR's code runs with those secrets (the "pwn request")
  push                 base branch workflow with secrets (environment secrets only if the job names
                       an environment and the branch is allowed)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

BASE_REPO = {
    "README.md": "Example repo.",
    "src/app.py": "print('app')",
    "Makefile": "test:\n\techo running tests\n\tpython tests/run.py\ndeploy:\n\techo deploying with token",
    "tests/run.py": "echo tests passed",
    "scripts/test.sh": "echo script tests passed",
    "conftest.py": "echo conftest loaded",
}
TRUSTED_HOSTS = {"github.com", "pypi.org"}
PROTECTED_PATHS = (".github/workflows/", "Makefile", "scripts/", "conftest.py", "tests/run.py")


@dataclass
class PullRequest:
    changes: dict[str, str]
    from_fork: bool = False
    approved_by_maintainer: bool = False
    reviewed_by_code_owner: bool = False


@dataclass
class Settings:
    require_fork_approval: bool = False
    protected_paths: tuple[str, ...] = ()       # needs code-owner review when a PR touches them
    environment_secrets_only_on_push: bool = False  # secrets live in a protected environment


@dataclass
class RunResult:
    blocked: str = ""
    network_log: list[tuple[str, str]] = field(default_factory=list)
    output: list[str] = field(default_factory=list)
    secrets_in_env: set[str] = field(default_factory=set)
    token_permissions: str = "write-all"

    def leaked(self, canary: str) -> bool:
        return any(canary in value for _, value in self.network_log)


def _triggers(wf: dict) -> list[str]:
    on = wf.get("on", wf.get(True))  # YAML 1.1 reads the key `on` as the boolean True
    if isinstance(on, str):
        return [on]
    return list(on) if on else []


def _expand(value: str, secrets: dict[str, str]) -> str:
    return re.sub(r"\$\{\{\s*secrets\.(\w+)\s*\}\}", lambda m: secrets.get(m.group(1), ""), str(value))


class Runner:
    def __init__(self, repo_secrets: dict[str, str], env_secrets: dict[str, str] | None = None,
                 settings: Settings | None = None) -> None:
        self.repo_secrets = repo_secrets
        self.env_secrets = env_secrets or {}
        self.settings = settings or Settings()

    def run(self, workflow_path: str, workflow_text: str, pr: PullRequest | None, event: str,
            base_files: dict[str, str] | None = None, branch: str = "pr") -> RunResult:
        base = dict(base_files or BASE_REPO)
        result = RunResult()
        s = self.settings
        if pr:
            if event == "pull_request" and pr.from_fork and s.require_fork_approval and not pr.approved_by_maintainer:
                result.blocked = "workflow run awaits maintainer approval"
                return result
            touched = [p for p in pr.changes if any(p.startswith(x) for x in s.protected_paths)]
            if touched and not pr.reviewed_by_code_owner:
                result.blocked = f"protected pipeline file changed ({touched[0]}): code-owner review required"
                return result
        merged = {**base, **(pr.changes if pr else {})}
        # Which workflow definition runs? PR merge result for pull_request, BASE for the others.
        definition = pr.changes.get(workflow_path, workflow_text) if (pr and event == "pull_request") else workflow_text
        wf = yaml.safe_load(definition)
        if event not in _triggers(wf):
            result.blocked = f"workflow not triggered by {event}"
            return result

        fork_pr = bool(pr and pr.from_fork and event == "pull_request")
        repo_secrets = {} if fork_pr else dict(self.repo_secrets)
        result.token_permissions = "read" if fork_pr else "write-all"
        if "permissions" in wf:
            perms = wf["permissions"]
            result.token_permissions = "read" if perms == {"contents": "read"} else str(perms)

        for job_name, job in wf.get("jobs", {}).items():
            if "if" in job and "refs/heads/main" in str(job["if"]) and branch != "main":
                continue
            secrets = dict(repo_secrets)
            env_name = job.get("environment")
            # Environment protection: its secrets go only to jobs that name the environment, and
            # (with a branch policy) only when the run is a push to an allowed branch, never a PR.
            if env_name and (not s.environment_secrets_only_on_push or event == "push"):
                secrets.update(self.env_secrets)
            env = {k: _expand(v, secrets) for k, v in (job.get("env") or {}).items()}
            workspace = dict(merged if (pr and event == "pull_request") else base)
            for step in job.get("steps", []):
                if "uses" in step and "checkout" in step["uses"]:
                    ref = str((step.get("with") or {}).get("ref", ""))
                    if "pull_request.head" in ref and pr:
                        workspace = dict(merged)  # the attacker's files are now on disk
                    continue
                step_env = {**env, **{k: _expand(v, secrets) for k, v in (step.get("env") or {}).items()}}
                result.secrets_in_env |= {k for k, v in step_env.items() if v}
                for line in str(step.get("run", "")).splitlines():
                    self._exec(line.strip(), step_env, workspace, result, 0)
        return result

    # ---- the fake shell ------------------------------------------------------------------
    def _exec(self, line: str, env: dict[str, str], ws: dict[str, str], res: RunResult, depth: int) -> None:
        if not line or depth > 5:
            return
        parts = line.split()
        cmd = parts[0]
        if cmd == "echo":
            res.output.append(" ".join(parts[1:]))
        elif cmd == "exfil" and len(parts) == 3:  # attacker command: send $NAME to host
            res.network_log.append((parts[2], env.get(parts[1], "")))
        elif cmd == "make" and len(parts) == 2:
            for recipe in self._make_target(ws.get("Makefile", ""), parts[1]):
                self._exec(recipe, env, ws, res, depth + 1)
        elif cmd in {"bash", "sh", "python"} and len(parts) >= 2:
            for inner in ws.get(parts[1], "").splitlines():
                self._exec(inner.strip(), env, ws, res, depth + 1)
        elif cmd == "pytest":
            for inner in ws.get("conftest.py", "").splitlines():  # conftest.py runs before tests
                self._exec(inner.strip(), env, ws, res, depth + 1)
        else:
            res.output.append(f"(ignored: {line})")

    @staticmethod
    def _make_target(makefile: str, target: str) -> list[str]:
        lines, found, recipes = makefile.splitlines(), False, []
        for ln in lines:
            if re.match(r"^[\w-]+:", ln):
                found = ln.startswith(target + ":")
            elif found and ln.startswith("\t"):
                recipes.append(ln.strip())
        return recipes


def lint_ppe(workflow_text: str) -> list[str]:
    """Static check for the dangerous combination (the real tools: zizmor, actionlint, CodeQL for Actions)."""
    wf = yaml.safe_load(workflow_text)
    findings = []
    triggers = _triggers(wf)
    for name, job in wf.get("jobs", {}).items():
        for step in job.get("steps", []):
            ref = str((step.get("with") or {}).get("ref", ""))
            if "checkout" in str(step.get("uses", "")) and "pull_request.head" in ref and "pull_request_target" in triggers:
                findings.append(f"PPE-1 {name}: pull_request_target checks out untrusted PR code")
        if "secrets." in str(job.get("env", "")) and "pull_request" in triggers and "environment" not in job:
            findings.append(f"PPE-2 {name}: repository secret in a job that runs on pull requests")
    if "permissions" not in wf:
        findings.append("PPE-3 workflow has no explicit least-privilege permissions")
    return findings
