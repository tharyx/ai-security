"""Harbor-style registry policy simulator: projects, robot accounts, immutable tags, severity-based prevent-pull. In memory."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

SEV_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class PolicyError(Exception):
    pass


@dataclass
class Robot:
    name: str
    project: str
    permissions: set  # {"push", "pull"}
    expires: date


@dataclass
class Project:
    name: str
    public: bool = False
    immutable_patterns: tuple = ()          # tag prefixes that cannot be overwritten, e.g. ("v", "release-")
    prevent_vulnerable: bool = False
    severity_threshold: str = "HIGH"         # block pull at or above this severity
    cve_allowlist: dict = field(default_factory=dict)  # cve -> expiry date
    require_signature: bool = False


@dataclass
class Artifact:
    repo: str
    tag: str
    digest: str
    vulns: list          # [(cve_id, severity)]
    signed: bool = False


class Registry:
    def __init__(self, today: date):
        self.today = today
        self.projects: dict[str, Project] = {}
        self.robots: dict[str, Robot] = {}
        self.artifacts: dict[tuple, Artifact] = {}

    def create_project(self, p: Project):
        self.projects[p.name] = p

    def create_robot(self, r: Robot):
        self.robots[r.name] = r

    def _auth(self, robot_name: str, project: str, perm: str):
        r = self.robots.get(robot_name)
        if not r:
            raise PolicyError("unknown robot account")
        if r.expires < self.today:
            raise PolicyError("robot account expired")
        if r.project != project or perm not in r.permissions:
            raise PolicyError(f"robot '{robot_name}' lacks '{perm}' on project '{project}'")

    def push(self, robot: str, art: Artifact):
        project = art.repo.split("/")[0]
        self._auth(robot, project, "push")
        p = self.projects[project]
        key = (art.repo, art.tag)
        if key in self.artifacts and any(art.tag.startswith(x) for x in p.immutable_patterns):
            raise PolicyError(f"tag '{art.tag}' is immutable and already exists")
        self.artifacts[key] = art

    def pull(self, robot: str | None, repo: str, tag: str) -> Artifact:
        project = repo.split("/")[0]
        p = self.projects[project]
        if robot is None:
            if not p.public:
                raise PolicyError("anonymous pull denied: project is private")
        else:
            self._auth(robot, project, "pull")
        art = self.artifacts.get((repo, tag))
        if art is None:
            raise PolicyError("not found")
        if p.require_signature and not art.signed:
            raise PolicyError("pull blocked: image is not signed")
        if p.prevent_vulnerable:
            limit = SEV_RANK[p.severity_threshold]
            for cve, sev in art.vulns:
                exp = p.cve_allowlist.get(cve)
                if exp and exp >= self.today:
                    continue
                if SEV_RANK[sev] >= limit:
                    raise PolicyError(f"pull blocked: {cve} ({sev}) at or above {p.severity_threshold}")
        return art
