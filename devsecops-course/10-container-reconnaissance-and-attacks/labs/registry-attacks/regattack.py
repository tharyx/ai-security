"""Registry attacks on three registry modes: open, authenticated-but-no-RBAC, and RBAC + immutable tags.

A registry is a Python object (no sockets). It mimics the Registry HTTP API v2 decisions:
GET /v2/_catalog, GET /v2/<repo>/tags/list, GET manifest, PUT manifest (push), DELETE manifest.
Link: csse-course/ch3 labs/attack-docker-registry covers token scopes and TLS in more depth.
"""
from __future__ import annotations

import hashlib
import json


def digest(m: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest()[:16]


class Registry:
    """mode: 'open' | 'auth-no-rbac' | 'rbac'."""

    def __init__(self, mode: str):
        self.mode = mode
        self.repos: dict[str, dict[str, dict]] = {}
        # identity -> permissions per repo pattern; used only in rbac mode
        self.users = {"alice-ci": {"shop/*": {"pull", "push"}}, "bob-dev": {"shop/*": {"pull"}}, "monitor": {"*": {"pull"}}}
        self.tokens = {"tok-alice": "alice-ci", "tok-bob": "bob-dev", "tok-mon": "monitor"}
        self.audit: list[str] = []

    def _allowed(self, token: str | None, repo: str | None, action: str) -> tuple[bool, int, str]:
        if self.mode == "open":
            return True, 200, "no authentication"
        user = self.tokens.get(token or "")
        if not user:
            return False, 401, "authentication required"
        if self.mode == "auth-no-rbac":
            return True, 200, f"{user} authenticated (every user can do everything)"
        if repo is None:
            return False, 403, "catalog needs registry:catalog scope"
        for pat, acts in self.users[user].items():
            if (pat == "*" or (pat.endswith("/*") and repo.startswith(pat[:-1]))) and action in acts:
                return True, 200, f"{user} allowed {action} on {repo}"
        return False, 403, f"{user} lacks {action} on {repo}"

    def catalog(self, token=None):
        if self.mode == "open":
            return 200, sorted(self.repos)
        user = self.tokens.get(token or "")
        if not user:
            return 401, "authentication required"
        if self.mode == "auth-no-rbac" or "*" in self.users[user]:
            return 200, sorted(self.repos)
        return 403, "catalog scope required"

    def tags(self, repo, token=None):
        ok, code, why = self._allowed(token, repo, "pull")
        return (200, sorted(self.repos.get(repo, {}))) if ok else (code, why)

    def pull(self, repo, tag, token=None):
        ok, code, why = self._allowed(token, repo, "pull")
        if not ok:
            return code, why
        return (200, self.repos[repo][tag]) if tag in self.repos.get(repo, {}) else (404, "manifest unknown")

    def push(self, repo, tag, manifest, token=None):
        ok, code, why = self._allowed(token, repo, "push")
        if not ok:
            return code, why
        if self.mode == "rbac" and tag in self.repos.get(repo, {}):
            return 409, "tag is immutable"
        self.repos.setdefault(repo, {})[tag] = manifest
        self.audit.append(f"push {repo}:{tag} {digest(manifest)}")
        return 201, digest(manifest)

    def delete(self, repo, tag, token=None):
        ok, code, why = self._allowed(token, repo, "delete")
        if not ok:
            return code, why
        self.repos.get(repo, {}).pop(tag, None)
        return 202, "deleted"


def seed(reg: Registry) -> Registry:
    """Load images directly (the registry admin's own bulk import)."""
    reg.repos = {
        "shop/web": {"1.0": {"layers": ["l1", "l2"], "env": ["MODE=prod"]}},
        "shop/api": {"1.0": {"layers": ["l1", "l3"], "env": ["DB_PASSWORD=canary-registry-pw"]}},
        "hr/payroll": {"5": {"layers": ["l9"], "env": []}},
    }
    return reg


def attack(reg: Registry, token: str | None = None) -> dict:
    """What an attacker with this token (or none) can do. Each step is an API call."""
    r: dict = {}
    code, body = reg.catalog(token)
    r["enumerate catalog"] = (code, body if code == 200 else body)
    repos = body if code == 200 else ["shop/api", "shop/web", "hr/payroll"]   # attacker guesses common names if the catalog is closed
    leaked = []
    for repo in repos:
        c, tags = reg.tags(repo, token)
        if c != 200:
            continue
        for t in tags:
            c2, m = reg.pull(repo, t, token)
            if c2 == 200:
                for e in m.get("env", []):
                    if "PASSWORD" in e.upper() or "TOKEN" in e.upper():
                        leaked.append(f"{repo}:{t} {e.split('=')[0]}")
    r["secrets in configs"] = leaked
    poisoned = {"layers": ["l1", "l2", "canary-extra-layer"], "env": ["MODE=prod"]}
    r["overwrite shop/web:1.0"] = reg.push("shop/web", "1.0", poisoned, token)[0]
    r["delete shop/api:1.0"] = reg.delete("shop/api", "1.0", token)[0]
    return r
