"""Continuous deployment model: environments, a protected prod approval, and rollback.

Everything is in memory. Nothing is deployed anywhere.

Rules enforced:
  * An artifact is identified by a sha256 digest; every environment gets that same digest (promote, not rebuild).
  * dev and staging deploy automatically. prod is PROTECTED: it needs an approval by an allowed approver
    who is not the person who triggered the deployment, on a protected branch, for the exact digest
    that is waiting, within a time window.
  * A failed health check rolls the environment back to the previous good release automatically.
  * A manual rollback re-deploys an earlier release (never a rebuild) and is logged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

ENV_ORDER = ["dev", "staging", "prod"]


class DeployError(Exception):
    pass


def digest_of(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()


@dataclass
class Release:
    version: str
    digest: str
    deployed_by: str
    status: str = "active"  # active | superseded | rolled_back


@dataclass
class Environment:
    name: str
    protected: bool = False
    approvers: set = field(default_factory=set)
    history: list = field(default_factory=list)

    @property
    def current(self):
        for r in reversed(self.history):
            if r.status == "active":
                return r
        return None


class DeploymentSystem:
    def __init__(self, clock=lambda: 0.0, approval_ttl=3600, protected_branches=("main",)):
        self.clock = clock
        self.approval_ttl = approval_ttl
        self.protected_branches = set(protected_branches)
        self.envs = {n: Environment(n) for n in ENV_ORDER}
        self.envs["prod"].protected = True
        self.envs["prod"].approvers = {"release-manager", "security-lead"}
        self.artifacts = {}  # version -> digest, registered by CI
        self.pending = {}  # (env, version) -> dict(requested_by, digest, time, approvals)
        self.audit = []

    def log(self, event, **kw):
        self.audit.append({"t": self.clock(), "event": event, **kw})

    # --- CI hands over an artifact -------------------------------------------------
    def register_artifact(self, version: str, content: str) -> str:
        d = digest_of(content)
        self.artifacts[version] = d
        self.log("artifact_registered", version=version, digest=d)
        return d

    # --- deploy ---------------------------------------------------------------------
    def deploy(self, env: str, version: str, by: str, branch: str = "main", digest: str | None = None,
               healthy=lambda release: True):
        e = self.envs[env]
        if version not in self.artifacts:
            raise DeployError(f"unknown version {version}: it was never built by CI")
        d = self.artifacts[version]
        if digest is not None and digest != d:
            raise DeployError("digest mismatch: the artifact is not the one CI built")
        idx = ENV_ORDER.index(env)
        if idx > 0:
            lower = self.envs[ENV_ORDER[idx - 1]].current
            if not lower or lower.version != version:
                raise DeployError(f"{version} must be deployed to {ENV_ORDER[idx - 1]} first")
        if e.protected:
            if branch not in self.protected_branches:
                raise DeployError(f"branch {branch!r} is not protected; prod deploys only from protected branches")
            self._require_approval(e, version, d, by)
        return self._release(e, version, d, by, healthy)

    def request_approval(self, env: str, version: str, by: str):
        if version not in self.artifacts:
            raise DeployError("unknown version")
        self.pending[(env, version)] = {"by": by, "digest": self.artifacts[version],
                                        "time": self.clock(), "approvals": {}}
        self.log("approval_requested", env=env, version=version, by=by)

    def approve(self, env: str, version: str, approver: str):
        p = self.pending.get((env, version))
        if not p:
            raise DeployError("nothing is waiting for approval")
        if approver not in self.envs[env].approvers:
            raise DeployError(f"{approver} is not an approver for {env}")
        if approver == p["by"]:
            raise DeployError("separation of duties: you cannot approve your own deployment")
        p["approvals"][approver] = self.clock()
        self.log("approved", env=env, version=version, approver=approver, digest=p["digest"])

    def _require_approval(self, e, version, digest, by):
        p = self.pending.get((e.name, version))
        if not p or not p["approvals"]:
            raise DeployError(f"{e.name} is protected: manual approval required")
        if p["by"] != by:
            raise DeployError("only the person who requested the deployment can run it")
        if p["digest"] != digest:
            raise DeployError("approval was for a different digest")
        if self.clock() - max(p["approvals"].values()) > self.approval_ttl:
            raise DeployError("approval expired")
        del self.pending[(e.name, version)]  # single use

    def _release(self, e, version, digest, by, healthy):
        previous = e.current
        rel = Release(version, digest, by)
        if previous:
            previous.status = "superseded"
        e.history.append(rel)
        self.log("deployed", env=e.name, version=version, digest=digest, by=by)
        if not healthy(rel):
            rel.status = "rolled_back"
            self.log("health_check_failed", env=e.name, version=version)
            if previous:
                previous.status = "active"
                self.log("auto_rollback", env=e.name, to=previous.version)
            return "rolled_back"
        return "deployed"

    # --- rollback -------------------------------------------------------------------
    def rollback(self, env: str, to_version: str, by: str):
        e = self.envs[env]
        if e.protected and by not in e.approvers:
            raise DeployError(f"{by} may not roll back {env}")
        target = next((r for r in reversed(e.history) if r.version == to_version and r.status != "rolled_back"), None)
        if not target:
            raise DeployError(f"{to_version} was never successfully deployed to {env}")
        cur = e.current
        if cur:
            cur.status = "superseded"
        e.history.append(Release(target.version, target.digest, by))
        self.log("manual_rollback", env=env, to=to_version, by=by)
        return e.current

    def state(self):
        return {n: (e.current.version if e.current else None) for n, e in self.envs.items()}
