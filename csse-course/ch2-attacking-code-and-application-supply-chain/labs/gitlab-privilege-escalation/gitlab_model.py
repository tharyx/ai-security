"""A SIMULATED GitLab-style permission model (concept only, hedged).

This is NOT GitLab. Real GitLab has many more rules, and they change by version and edition
(verify at docs.gitlab.com). The model keeps just enough to teach three classic escalation paths:

  1. A protected CI/CD variable that is not really protected (flag off), so any Developer can make
     a pipeline on their own branch print it.
  2. A protected branch that lets Developers push, so a Developer changes the pipeline file that runs
     on the protected branch with protected variables.
  3. A pipeline trigger token (or job token) that is visible to or usable by too low a role or scope,
     so a low-privilege identity runs a pipeline on a protected ref.

An auditor lists these misconfigurations and `harden()` fixes them. No network, nothing real.
"""

from __future__ import annotations

from dataclasses import dataclass, field

LEVELS = {"Guest": 10, "Reporter": 20, "Developer": 30, "Maintainer": 40, "Owner": 50}
NO_ONE = 0


@dataclass
class Variable:
    key: str
    value: str  # FAKE values only in this lab
    protected: bool = False  # only exposed to pipelines on protected branches/tags
    masked: bool = False  # hidden in job logs (a weak control: it can be bypassed by encoding)


@dataclass
class ProtectedBranch:
    name: str
    push_level: int = LEVELS["Maintainer"]
    merge_level: int = LEVELS["Maintainer"]


@dataclass
class TriggerToken:
    owner: str
    # minimum role allowed to USE (see/run) this token. Real GitLab differs; this is the concept.
    usable_by_level: int = LEVELS["Maintainer"]
    can_run_on_protected: bool = True


@dataclass
class Project:
    name: str
    members: dict[str, str] = field(default_factory=dict)  # user -> role name
    branches: list[str] = field(default_factory=lambda: ["main"])
    protected: dict[str, ProtectedBranch] = field(default_factory=dict)
    variables: list[Variable] = field(default_factory=list)
    trigger_tokens: list[TriggerToken] = field(default_factory=list)
    job_token_allowlist_enabled: bool = True
    job_token_allowlist: set[str] = field(default_factory=set)  # other projects allowed to use a job token here
    ci_file: dict[str, str] = field(default_factory=lambda: {"main": "script: [make test]"})  # per-branch CI config

    def level(self, user: str) -> int:
        return LEVELS.get(self.members.get(user, ""), NO_ONE)

    def is_protected(self, branch: str) -> bool:
        return branch in self.protected

    # ---- actions ----
    def can_push(self, user: str, branch: str) -> bool:
        lvl = self.level(user)
        if branch in self.protected:
            return lvl >= self.protected[branch].push_level and lvl > NO_ONE
        return lvl >= LEVELS["Developer"]

    def push_ci_file(self, user: str, branch: str, content: str) -> bool:
        if branch not in self.branches:
            if self.level(user) < LEVELS["Developer"]:
                return False
            self.branches.append(branch)  # Developers may create unprotected branches
        if not self.can_push(user, branch):
            return False
        self.ci_file[branch] = content
        return True

    def variables_for_ref(self, ref: str) -> dict[str, str]:
        prot = self.is_protected(ref)
        return {v.key: v.value for v in self.variables if (not v.protected) or prot}

    def run_pipeline_as(self, user: str, ref: str) -> dict[str, str]:
        """The pipeline runs the CI file of `ref` with the variables that `ref` is allowed to see.
        A job that prints its environment leaks whatever is in that dict."""
        if self.level(user) < LEVELS["Developer"]:
            return {}
        return self.variables_for_ref(ref)

    def trigger_pipeline(self, user: str, token_index: int, ref: str) -> dict[str, str]:
        tok = self.trigger_tokens[token_index]
        if self.level(user) < tok.usable_by_level or self.level(user) == NO_ONE:
            return {}
        if self.is_protected(ref) and not tok.can_run_on_protected:
            return {}
        return self.variables_for_ref(ref)

    def job_token_access(self, from_project: str) -> bool:
        """May a CI job in `from_project` use its job token to read THIS project?"""
        if not self.job_token_allowlist_enabled:
            return True  # any project's job could reach in
        return from_project in self.job_token_allowlist


@dataclass
class Finding:
    id: str
    severity: str
    detail: str


def audit(p: Project) -> list[Finding]:
    out: list[Finding] = []
    for v in p.variables:
        looks_secret = any(w in v.key.upper() for w in ("TOKEN", "SECRET", "KEY", "PASSWORD", "DEPLOY"))
        if looks_secret and not v.protected:
            out.append(Finding("VAR-UNPROTECTED", "high", f"secret-like variable {v.key} is not protected"))
        if looks_secret and v.protected and not v.masked:
            out.append(Finding("VAR-UNMASKED", "low", f"{v.key} is protected but not masked in logs"))
    for name, pb in p.protected.items():
        if pb.push_level <= LEVELS["Developer"]:
            out.append(Finding("BRANCH-DEV-PUSH", "high", f"protected branch {name} lets Developers push"))
        if pb.merge_level <= LEVELS["Developer"]:
            out.append(Finding("BRANCH-DEV-MERGE", "medium", f"protected branch {name} lets Developers merge without review"))
    if "main" not in p.protected:
        out.append(Finding("BRANCH-MAIN-UNPROTECTED", "high", "default branch main is not protected"))
    for i, t in enumerate(p.trigger_tokens):
        if t.usable_by_level < LEVELS["Maintainer"] and t.can_run_on_protected:
            out.append(Finding("TRIGGER-LOW-ROLE", "high", f"trigger token #{i} usable by role level {t.usable_by_level} on protected refs"))
    if not p.job_token_allowlist_enabled:
        out.append(Finding("JOBTOKEN-OPEN", "medium", "CI job token allowlist is off: other projects' jobs can reach this project"))
    return out


def harden(p: Project) -> None:
    for v in p.variables:
        if any(w in v.key.upper() for w in ("TOKEN", "SECRET", "KEY", "PASSWORD", "DEPLOY")):
            v.protected = True
            v.masked = True
    p.protected.setdefault("main", ProtectedBranch("main"))
    for pb in p.protected.values():
        pb.push_level = max(pb.push_level, LEVELS["Maintainer"])
        pb.merge_level = max(pb.merge_level, LEVELS["Maintainer"])
    for t in p.trigger_tokens:
        t.usable_by_level = max(t.usable_by_level, LEVELS["Maintainer"])
    p.job_token_allowlist_enabled = True


def misconfigured_project() -> Project:
    return Project(
        name="payments",
        members={"olga": "Owner", "mike": "Maintainer", "dave": "Developer", "rita": "Reporter", "gus": "Guest"},
        protected={"main": ProtectedBranch("main", push_level=LEVELS["Developer"], merge_level=LEVELS["Developer"])},
        variables=[
            Variable("DEPLOY_TOKEN", "FAKE-deploy-token-0001", protected=False),
            Variable("SIGNING_KEY", "FAKE-signing-key-0002", protected=True, masked=False),
            Variable("APP_ENV", "staging"),
        ],
        trigger_tokens=[TriggerToken("mike", usable_by_level=LEVELS["Developer"], can_run_on_protected=True)],
        job_token_allowlist_enabled=False,
    )
