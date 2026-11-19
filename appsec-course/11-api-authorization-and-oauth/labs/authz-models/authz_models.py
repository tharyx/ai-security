"""Five authorization models side by side: none, RBAC, DAC, ABAC and ReBAC.

Pure standard library. Every model answers the same question:
    may SUBJECT do ACTION on RESOURCE?

DBA analogies:
- RBAC  ~ Oracle roles: GRANT role TO user; roles granted to roles form a hierarchy.
- DAC   ~ object privileges: the owner runs GRANT SELECT ON t TO u [WITH GRANT OPTION].
- ABAC  ~ a VPD / row-level-security predicate built from user and row attributes.
- ReBAC ~ a join over a "relationship tuples" table (Google Zanzibar, OpenFGA, SpiceDB).
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------- no authorization


def no_authz(subject: str, action: str, resource: str) -> bool:
    """'Authenticated means allowed'. The model behind most BOLA/BFLA bugs."""
    return True


# ---------------------------------------------------------------- RBAC

ROLE_PERMS: dict[str, set[str]] = {
    "viewer": {"doc:read"},
    "editor": {"doc:write"},
    "admin": {"doc:delete", "user:manage"},
}
# admin inherits editor, editor inherits viewer (like GRANT editor TO admin)
ROLE_PARENTS: dict[str, list[str]] = {"admin": ["editor"], "editor": ["viewer"]}


def rbac_permissions(roles: set[str]) -> set[str]:
    """Expand a user's roles through the hierarchy and collect permissions."""
    seen: set[str] = set()
    stack = list(roles)
    perms: set[str] = set()
    while stack:
        r = stack.pop()
        if r in seen:
            continue
        seen.add(r)
        perms |= ROLE_PERMS.get(r, set())
        stack.extend(ROLE_PARENTS.get(r, []))
    return perms


def rbac_allows(user_roles: set[str], permission: str) -> bool:
    return permission in rbac_permissions(user_roles)


# ---------------------------------------------------------------- DAC


@dataclass
class DacStore:
    """Owner-controlled ACLs. Only the owner, or a grantee WITH GRANT OPTION, may grant."""

    owners: dict[str, str] = field(default_factory=dict)
    acl: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    grant_option: dict[str, set[str]] = field(default_factory=dict)

    def create(self, owner: str, resource: str) -> None:
        self.owners[resource] = owner
        self.acl[resource] = {owner: {"read", "write", "delete"}}
        self.grant_option[resource] = {owner}

    def grant(self, by: str, resource: str, to: str, action: str, with_grant_option: bool = False) -> bool:
        if by not in self.grant_option.get(resource, set()):
            return False  # ORA-01031 insufficient privileges
        self.acl[resource].setdefault(to, set()).add(action)
        if with_grant_option:
            self.grant_option[resource].add(to)
        return True

    def revoke(self, by: str, resource: str, frm: str, action: str) -> bool:
        if by != self.owners.get(resource):
            return False
        self.acl[resource].get(frm, set()).discard(action)
        return True

    def check(self, subject: str, action: str, resource: str) -> bool:
        return action in self.acl.get(resource, {}).get(subject, set())


# ---------------------------------------------------------------- ABAC


def abac_allows(subject: dict, action: str, resource: dict, env: dict) -> tuple[bool, str]:
    """Attribute rules. Returns (decision, reason) so the decision is explainable."""
    if subject.get("suspended"):
        return False, "subject suspended"
    if subject.get("clearance", 0) < resource.get("classification", 0):
        return False, "clearance below classification"
    if subject.get("department") != resource.get("department") and "auditor" not in subject.get("roles", []):
        return False, "different department"
    if action in ("write", "delete") and not (9 <= env.get("hour", 12) < 18):
        return False, "writes only in business hours"
    if action == "delete" and "manager" not in subject.get("roles", []):
        return False, "only managers delete"
    return True, "all attribute rules passed"


# ---------------------------------------------------------------- ReBAC (Zanzibar style)

# relation rewrites: having the right side implies the left side
IMPLIED_BY = {"viewer": ["editor"], "editor": ["owner"]}
# a viewer of the parent folder is a viewer of the document
INHERIT_FROM_PARENT = {"viewer", "editor"}


@dataclass
class ReBAC:
    """Tuples look like (object, relation, subject). A subject can be a user
    ("user:alice") or a userset ("group:eng#member")."""

    tuples: set[tuple[str, str, str]] = field(default_factory=set)

    def write(self, obj: str, relation: str, subject: str) -> None:
        self.tuples.add((obj, relation, subject))

    def check(self, obj: str, relation: str, user: str, _depth: int = 0) -> bool:
        if _depth > 10:  # protects against cycles and very deep graphs
            return False
        for o, r, s in self.tuples:
            if o != obj or r != relation:
                continue
            if s == user:
                return True
            if "#" in s:  # userset: group:eng#member
                g_obj, g_rel = s.split("#", 1)
                if self.check(g_obj, g_rel, user, _depth + 1):
                    return True
        for stronger in IMPLIED_BY.get(relation, []):
            if self.check(obj, stronger, user, _depth + 1):
                return True
        if relation in INHERIT_FROM_PARENT:
            for o, r, s in self.tuples:
                if o == obj and r == "parent" and self.check(s, relation, user, _depth + 1):
                    return True
        return False


def sample_rebac() -> ReBAC:
    z = ReBAC()
    z.write("group:eng", "member", "user:alice")
    z.write("group:eng", "member", "user:bob")
    z.write("folder:roadmaps", "viewer", "group:eng#member")
    z.write("doc:q3-plan", "parent", "folder:roadmaps")
    z.write("doc:q3-plan", "owner", "user:carol")
    z.write("doc:salaries", "owner", "user:carol")
    return z
