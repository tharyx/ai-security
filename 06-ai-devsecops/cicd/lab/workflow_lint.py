"""A GitHub Actions workflow linter focused on supply-chain and AI-release risks.

    python workflow_lint.py .github/workflows/*.yml [--release release.yml]

``--release`` marks workflows that ship to production. For those, the linter also checks
that the AI secure-delivery stages exist (secret scan, SAST, dependency audit, model scan,
AI eval, SBOM, signing/provenance).

Gotcha worth knowing: YAML 1.1 (PyYAML) reads the key ``on:`` as the boolean True.
Every tool that parses workflows has to handle that; see ``triggers()``.

Real tools for this job: zizmor, actionlint, OpenSSF Scorecard, GitHub's own code
scanning for Actions. The ideas are the same.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

import yaml

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
FULL_SHA = re.compile(r"@[0-9a-f]{40}$")
# Event fields an outside contributor can control (titles, bodies, branch names, commit messages...).
UNTRUSTED = re.compile(
    r"\$\{\{[^}]*(github\.event\.[\w.\[\]*-]*\.(title|body|message|ref|label|name|email|head_branch|"
    r"page_name|default_branch|display_title)\b|github\.head_ref)[^}]*\}\}")
PR_HEAD = re.compile(r"github\.event\.pull_request\.head|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head")
PIPE_TO_SHELL = re.compile(r"(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
LONG_LIVED = re.compile(r"secrets\.(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_CREDENTIALS|AZURE_CLIENT_SECRET"
                        r"|GCP_SA_KEY|GCP_CREDENTIALS|GOOGLE_CREDENTIALS)\b", re.I)
SECURITY_STEP = re.compile(r"secur|scan|audit|eval|injection|sast|bandit|semgrep|codeql|gitleaks|trivy"
                           r"|release_gate|pip-audit|cosign|verify", re.I)
RELEASE_STAGES = {
    "secret scan": re.compile(r"gitleaks|trufflehog|detect-secrets", re.I),
    "SAST": re.compile(r"bandit|semgrep|codeql", re.I),
    "dependency audit": re.compile(r"pip-audit|osv-scanner|dependency-review", re.I),
    "model scan": re.compile(r"modelscan|pickle_scan", re.I),
    "AI security eval": re.compile(r"prompt-injection|promptfoo|garak|pyrit|release_gate", re.I),
    "SBOM": re.compile(r"sbom|cyclonedx|syft|spdx", re.I),
    "signing / provenance": re.compile(r"cosign|sigstore|attest-build-provenance|slsa-github-generator", re.I),
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    where: str      # file:job:step
    message: str


@dataclass
class Workflow:
    path: str
    data: dict
    release: bool = False

    def triggers(self) -> set[str]:
        on = self.data.get("on", self.data.get(True))  # PyYAML turns `on` into True
        if isinstance(on, str):
            return {on}
        return set(on or [])

    def jobs(self) -> Iterator[tuple[str, dict]]:
        yield from (self.data.get("jobs") or {}).items()

    def steps(self) -> Iterator[tuple[str, str, dict]]:
        for job_id, job in self.jobs():
            for i, step in enumerate(job.get("steps") or []):
                yield job_id, step.get("name") or step.get("uses") or f"step {i + 1}", step


def where(wf: Workflow, job: str = "", step: str = "") -> str:
    return ":".join(p for p in (Path(wf.path).name, job, step) if p)


def step_text(step: dict) -> str:
    parts = [str(step.get(k, "")) for k in ("name", "uses", "run")]
    parts += [str(v) for v in (step.get("with") or {}).values()]
    return " ".join(parts)


# --------------------------------------------------------------------------- rules

Rule = Callable[[Workflow], Iterator[tuple[str, str]]]
RULES: dict[str, tuple[str, str, Rule]] = {}


def rule(rule_id: str, severity: str, title: str) -> Callable[[Rule], Rule]:
    def register(fn: Rule) -> Rule:
        RULES[rule_id] = (severity, title, fn)
        return fn
    return register


@rule("GHA-001", "HIGH", "Action not pinned to a full commit SHA")
def pin_sha(wf: Workflow):
    for job_id, name, step in wf.steps():
        uses = step.get("uses")
        if uses and not uses.startswith(("./", "docker://")) and not FULL_SHA.search(uses):
            yield where(wf, job_id, name), f"'{uses}': a tag or branch can be moved to different code"


@rule("GHA-002", "MEDIUM", "GITHUB_TOKEN permissions not least-privilege")
def permissions(wf: Workflow):
    top = wf.data.get("permissions")
    if top in ("write-all", "read-all|write-all"):
        yield where(wf), "permissions: write-all"
    elif isinstance(top, dict) and any(v == "write" for v in top.values()):
        yield where(wf), f"workflow-level write scopes {sorted(k for k, v in top.items() if v == 'write')}; grant writes per job"
    elif top is None:
        for job_id, job in wf.jobs():
            if job.get("permissions") is None:
                yield where(wf, job_id), "no permissions block: the token gets the repository default"


@rule("GHA-003", "CRITICAL", "Privileged trigger checks out untrusted PR code ('pwn request')")
def pwn_request(wf: Workflow):
    if not wf.triggers() & {"pull_request_target", "workflow_run"}:
        return
    for job_id, name, step in wf.steps():
        if str(step.get("uses", "")).startswith("actions/checkout") and PR_HEAD.search(str((step.get("with") or {}).get("ref", ""))):
            yield where(wf, job_id, name), "fork code runs with secrets and a write token"


@rule("GHA-004", "HIGH", "Untrusted input expanded inside a script")
def script_injection(wf: Workflow):
    for job_id, name, step in wf.steps():
        for text in (step.get("run"), (step.get("with") or {}).get("script")):
            for m in UNTRUSTED.finditer(str(text or "")):
                yield where(wf, job_id, name), f"{m.group(0)} is pasted into code; pass it through env: instead"


@rule("GHA-005", "HIGH", "Long-lived cloud credentials")
def long_lived_keys(wf: Workflow):
    for job_id, name, step in wf.steps():
        blob = step_text(step) + " " + " ".join(str(v) for v in (step.get("env") or {}).values())
        for m in LONG_LIVED.finditer(blob):
            yield where(wf, job_id, name), f"{m.group(0)}: use OIDC federation (id-token: write + role-to-assume)"


@rule("GHA-006", "HIGH", "Security gate cannot fail the build")
def soft_gate(wf: Workflow):
    for job_id, job in wf.jobs():
        if job.get("continue-on-error") is True:
            yield where(wf, job_id), "whole job is continue-on-error"
        for i, step in enumerate(job.get("steps") or []):
            name = step.get("name") or step.get("uses") or f"step {i + 1}"
            if not SECURITY_STEP.search(step_text(step)):
                continue
            if step.get("continue-on-error") is True or re.search(r"\|\|\s*(true|exit 0)", str(step.get("run", ""))):
                yield where(wf, job_id, name), "a failing security check is ignored"


@rule("GHA-007", "HIGH", "Remote script piped to a shell")
def pipe_to_shell(wf: Workflow):
    for job_id, name, step in wf.steps():
        if PIPE_TO_SHELL.search(str(step.get("run", ""))):
            yield where(wf, job_id, name), "curl | bash in CI runs with the job's token and secrets"


@rule("GHA-008", "LOW", "Checkout keeps the token on disk")
def persist_credentials(wf: Workflow):
    for job_id, name, step in wf.steps():
        if str(step.get("uses", "")).startswith("actions/checkout"):
            if (step.get("with") or {}).get("persist-credentials") is not False:
                yield where(wf, job_id, name), "set persist-credentials: false so later steps can't read the token"


@rule("GHA-009", "MEDIUM", "Release pipeline missing an AI secure-delivery stage")
def release_stages(wf: Workflow):
    if not wf.release:
        return
    text = " ".join(step_text(s) for _, _, s in wf.steps())
    for stage, pattern in RELEASE_STAGES.items():
        if not pattern.search(text):
            yield where(wf), f"no {stage} stage"


@rule("GHA-010", "MEDIUM", "Deploy job without a protected environment")
def deploy_environment(wf: Workflow):
    for job_id, job in wf.jobs():
        if "deploy" in f"{job_id} {job.get('name', '')}".lower() and not job.get("environment"):
            yield where(wf, job_id), "no environment: no required reviewers, no branch rule, no scoped secrets"


@rule("GHA-011", "HIGH", "Self-hosted runner reachable from pull requests")
def self_hosted(wf: Workflow):
    if not wf.triggers() & {"pull_request", "pull_request_target"}:
        return
    for job_id, job in wf.jobs():
        runs_on = job.get("runs-on")
        labels = runs_on if isinstance(runs_on, list) else [runs_on]
        if "self-hosted" in labels:
            yield where(wf, job_id), "PR code can persist on a self-hosted machine and reach its network"


# --------------------------------------------------------------------------- engine

def load(path: str | Path, release: bool = False) -> Workflow:
    return Workflow(str(path), yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}, release)


def lint(wf: Workflow, *, disabled: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    findings = []
    for rule_id, (severity, _title, fn) in sorted(RULES.items()):
        if rule_id not in disabled:
            findings += [Finding(rule_id, severity, w, msg) for w, msg in fn(wf)]
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint GitHub Actions workflows.")
    parser.add_argument("workflows", nargs="*", help="ordinary workflows")
    parser.add_argument("--release", action="append", default=[], help="workflow that ships to production")
    parser.add_argument("--disable", action="append", default=[])
    parser.add_argument("--fail-on", default="HIGH", choices=list(SEVERITY))
    args = parser.parse_args(argv)
    workflows = [load(p) for p in args.workflows] + [load(p, release=True) for p in args.release]
    findings = [f for wf in workflows for f in lint(wf, disabled=set(args.disable))]
    for f in findings:
        print(f"{f.severity:8} {f.rule_id}  {f.where}: {f.message}")
    failed = any(SEVERITY[f.severity] >= SEVERITY[args.fail_on] for f in findings)
    print(f"\n{'FAIL' if failed else 'PASS'}: {len(findings)} finding(s), fail-on={args.fail_on}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
