"""Designing API permissions and OAuth scopes, checked as code.

1. `lint_spec()` reads an API spec (endpoints with the scope each needs) and client registrations,
   and reports design problems: missing scopes, write endpoints guarded by read scopes, admin
   endpoints guarded by ordinary scopes, over-broad scopes, clients granted more than they use.
2. `matrix()` prints the scope -> endpoint matrix that reviewers sign off.
3. `authorize_vulnerable()` vs `authorize_secure()` enforce the design at request time.
   The secure version is deny-by-default, checks the scope, intersects scopes with the user's
   role permissions (a scope is a ceiling, never a grant) and checks object ownership.

Pure standard library. Scope names follow the common `resource:action` convention.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
BROAD_SCOPES = {"*", "api", "all", "full_access", "admin"}
SCOPE_RE = re.compile(r"^[a-z][a-z0-9_-]*:(read|write|delete|admin)$")


@dataclass
class Finding:
    id: str
    severity: str
    message: str


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _route_regex(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\{[^}]+\}", r"(?P<id>[^/]+)", path) + "$")


def find_endpoint(spec: dict, method: str, path: str) -> tuple[dict | None, str | None]:
    for ep in spec["endpoints"]:
        m = _route_regex(ep["path"]).match(path)
        if m and ep["method"] == method:
            return ep, m.groupdict().get("id")
    return None, None


# ------------------------------------------------------------------ design lint
def lint_spec(spec: dict, clients: dict | None = None) -> list[Finding]:
    f: list[Finding] = []
    defined = set(spec.get("scopes", {}))
    for s in sorted(defined):
        if s in BROAD_SCOPES:
            f.append(Finding("SCOPE-04", "HIGH", f"over-broad scope '{s}' defined: one token can do everything"))
        elif not SCOPE_RE.match(s):
            f.append(Finding("SCOPE-06", "LOW", f"scope '{s}' does not follow resource:action naming"))
    for ep in spec["endpoints"]:
        name = f"{ep['method']} {ep['path']}"
        scopes = ep.get("scopes", [])
        if ep.get("public"):
            if ep["method"] in WRITE_METHODS:
                f.append(Finding("SCOPE-07", "HIGH", f"{name}: public write endpoint"))
            continue
        if not scopes:
            f.append(Finding("SCOPE-01", "CRITICAL", f"{name}: no scope required (any valid token works)"))
            continue
        for s in scopes:
            if s not in defined:
                f.append(Finding("SCOPE-08", "MEDIUM", f"{name}: uses undefined scope '{s}'"))
        if ep["method"] in WRITE_METHODS and all(s.endswith(":read") for s in scopes):
            f.append(Finding("SCOPE-02", "HIGH", f"{name}: write method guarded only by a read scope"))
        if ep.get("admin") and not any(s.endswith(":admin") for s in scopes):
            f.append(Finding("SCOPE-03", "HIGH", f"{name}: admin function reachable with a non-admin scope (BFLA)"))
        if "{" in ep["path"] and not ep.get("owner_check"):
            f.append(Finding("SCOPE-09", "CRITICAL", f"{name}: object id in path but no owner check (BOLA)"))
    for cid, c in (clients or {}).items():
        needed = set()
        for e in c.get("uses", []):
            method, path = e.split(" ", 1)
            ep = next((x for x in spec["endpoints"] if x["method"] == method and x["path"] == path), None)
            if ep:
                needed |= set(ep.get("scopes", []))
        extra = set(c["granted"]) - needed
        if extra:
            f.append(Finding("SCOPE-05", "MEDIUM", f"client '{cid}' granted unused scopes: {', '.join(sorted(extra))}"))
    return f


def matrix(spec: dict) -> str:
    scopes = sorted(spec.get("scopes", {}))
    rows = ["| Endpoint | " + " | ".join(scopes) + " |", "|---|" + "---|" * len(scopes)]
    for ep in spec["endpoints"]:
        cells = ["public" if ep.get("public") and i == 0 else ("X" if s in ep.get("scopes", []) else "")
                 for i, s in enumerate(scopes)]
        rows.append(f"| {ep['method']} {ep['path']} | " + " | ".join(cells) + " |")
    return "\n".join(rows)


# ------------------------------------------------------------------ enforcement
@dataclass
class Decision:
    allow: bool
    reason: str


def authorize_vulnerable(claims: dict | None, method: str, path: str, spec: dict, owner_of=None) -> Decision:
    """VULNERABLE: 'a valid token is enough'. No scope check, no owner check, unknown routes pass."""
    if not claims:
        return Decision(False, "no token")
    return Decision(True, "token present")


def authorize_secure(claims: dict | None, method: str, path: str, spec: dict, owner_of=None) -> Decision:
    ep, obj_id = find_endpoint(spec, method, path)
    if ep is None:
        return Decision(False, "unknown route: deny by default")
    if ep.get("public"):
        return Decision(True, "public endpoint")
    if not claims:
        return Decision(False, "no token")
    token_scopes = set(claims.get("scope", "").split())
    role_perms = set()
    for role in claims.get("roles", []):
        role_perms |= set(spec.get("roles", {}).get(role, []))
    needed = set(ep.get("scopes", []))
    if not needed:
        return Decision(False, "endpoint has no scope defined: deny by default")
    if not needed <= token_scopes:
        return Decision(False, f"token lacks scope {sorted(needed - token_scopes)}")
    if not needed <= role_perms:
        return Decision(False, f"user role lacks permission {sorted(needed - role_perms)} (scope is a ceiling, not a grant)")
    if obj_id is not None and ep.get("owner_check"):
        owner = owner_of(obj_id) if owner_of else None
        if owner != claims.get("sub") and not any(s.endswith(":admin") for s in token_scopes & role_perms):
            return Decision(False, f"object {obj_id} belongs to {owner}, not {claims.get('sub')}")
    return Decision(True, "scope, role and ownership checks passed")
