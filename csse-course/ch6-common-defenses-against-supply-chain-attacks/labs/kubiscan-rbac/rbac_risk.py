"""KubiScan-style RBAC risk finder plus a kubectl-who-can style query. Reads YAML fixtures only."""

from __future__ import annotations

import yaml

RBAC_YAML = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: everything}
rules:
  - {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: secret-reader}
rules:
  - {apiGroups: [""], resources: ["secrets"], verbs: ["get", "list"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: pod-exec}
rules:
  - {apiGroups: [""], resources: ["pods/exec"], verbs: ["create"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: role-escalator}
rules:
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterroles", "clusterrolebindings"], verbs: ["bind", "escalate", "create"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: viewer}
rules:
  - {apiGroups: [""], resources: ["pods", "services"], verbs: ["get", "list", "watch"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ci-admin}
roleRef: {kind: ClusterRole, name: everything}
subjects:
  - {kind: ServiceAccount, name: ci-runner, namespace: build}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: anon-secrets}
roleRef: {kind: ClusterRole, name: secret-reader}
subjects:
  - {kind: Group, name: "system:unauthenticated"}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: default-sa-exec}
roleRef: {kind: ClusterRole, name: pod-exec}
subjects:
  - {kind: ServiceAccount, name: default, namespace: shop}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: dev-escalate}
roleRef: {kind: ClusterRole, name: role-escalator}
subjects:
  - {kind: User, name: dev@acme.example}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: team-view}
roleRef: {kind: ClusterRole, name: viewer}
subjects:
  - {kind: Group, name: "team-shop"}
"""

RISKY_VERBS = {"*", "create", "update", "patch", "delete", "bind", "escalate", "impersonate"}
ANON = {"system:anonymous", "system:unauthenticated"}
SEV = {"critical": 0, "high": 1, "medium": 2}


def load(text: str = RBAC_YAML):
    docs = [d for d in yaml.safe_load_all(text) if d]
    roles = {d["metadata"]["name"]: d for d in docs if d["kind"] in ("ClusterRole", "Role")}
    bindings = [d for d in docs if d["kind"] in ("ClusterRoleBinding", "RoleBinding")]
    return roles, bindings


def _allows(rule: dict, verb: str, resource: str) -> bool:
    verbs, res = rule.get("verbs", []), rule.get("resources", [])
    return ("*" in verbs or verb in verbs) and ("*" in res or resource in res)


def role_risks(role: dict):
    risks = []
    for rule in role.get("rules", []):
        v, r = set(rule["verbs"]), set(rule["resources"])
        if "*" in v and "*" in r:
            risks.append(("critical", "wildcard verbs and resources (cluster-admin equivalent)"))
        if "secrets" in r or "*" in r:
            if v & {"get", "list", "watch", "*"}:
                risks.append(("high", "can read secrets"))
        if "pods/exec" in r and "create" in v:
            risks.append(("high", "can exec into pods"))
        if v & {"bind", "escalate", "impersonate"}:
            risks.append(("critical", "can escalate privileges through RBAC verbs"))
        if "pods" in r and "create" in v:
            risks.append(("high", "can create pods (mount secrets, run privileged)"))
    return risks


def risky_subjects(roles, bindings):
    out = []
    for b in bindings:
        role = roles.get(b["roleRef"]["name"])
        if not role:
            continue
        risks = role_risks(role)
        for s in b["subjects"]:
            ident = f"{s['kind']}:{s.get('namespace', '-')}/{s['name']}"
            extra = []
            if s["name"] in ANON:
                extra.append(("critical", "granted to anonymous/unauthenticated users"))
            if s["kind"] == "ServiceAccount" and s["name"] == "default":
                extra.append(("medium", "bound to a namespace's default service account (every pod inherits it)"))
            for sev, why in risks + (extra if risks else []):
                out.append({"subject": ident, "binding": b["metadata"]["name"], "role": role["metadata"]["name"], "severity": sev, "why": why})
    return sorted(out, key=lambda r: (SEV[r["severity"]], r["subject"]))


def who_can(roles, bindings, verb: str, resource: str):
    """kubectl-who-can twin: list subjects that may do verb on resource."""
    subjects = set()
    for b in bindings:
        role = roles.get(b["roleRef"]["name"])
        if role and any(_allows(r, verb, resource) for r in role.get("rules", [])):
            subjects |= {f"{s['kind']}:{s['name']}" for s in b["subjects"]}
    return sorted(subjects)
