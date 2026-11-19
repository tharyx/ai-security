"""Find the RBAC and pod paths that lead to Kubernetes Secrets (analysis only; nothing is read or exploited).

Questions answered, per subject (user, group or service account) and namespace:
  Can they read Secrets directly?                     get / list / watch on secrets
  Can they make the cluster hand them a Secret?       create pods (mount it), patch workloads, pods/exec, serviceaccounts/token
  Can they become someone stronger?                   impersonate, escalate, bind, create rolebindings, nodes/proxy
And: which running pods carry a service-account token that has such power (so a bug in that app becomes a secrets breach)?
Real tools with similar ideas: kubectl-who-can, rbac-tool, Kubescape, KubiScan (check its maintenance status first).
"""
from __future__ import annotations

from dataclasses import dataclass

WORKLOAD_KINDS_RES = {"pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs"}


@dataclass(frozen=True)
class Path:
    subject: str
    namespace: str
    path_id: str
    severity: str
    why: str
    fix: str


def subject_keys(subjects: list[dict], binding_ns: str | None) -> list[str]:
    out = []
    for s in subjects or []:
        if s["kind"] == "ServiceAccount":
            out.append(f"sa:{s.get('namespace') or binding_ns}:{s['name']}")
        elif s["kind"] == "User":
            out.append(f"user:{s['name']}")
        else:
            out.append(f"group:{s['name']}")
    return out


def build_grants(docs: list[dict]) -> dict[str, list[tuple[str, dict]]]:
    """subject -> list of (namespace or '*', rule). A ClusterRoleBinding gives '*', a RoleBinding gives its namespace."""
    roles = {("Role", d["metadata"].get("namespace", ""), d["metadata"]["name"]): d.get("rules", []) for d in docs if d["kind"] == "Role"}
    croles = {d["metadata"]["name"]: d.get("rules", []) for d in docs if d["kind"] == "ClusterRole"}
    grants: dict[str, list[tuple[str, dict]]] = {}
    for d in docs:
        if d["kind"] not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        ns = d["metadata"].get("namespace") if d["kind"] == "RoleBinding" else "*"
        ref = d["roleRef"]
        rules = croles.get(ref["name"], []) if ref["kind"] == "ClusterRole" else roles.get(("Role", ns, ref["name"]), [])
        for key in subject_keys(d.get("subjects"), ns if ns != "*" else None):
            grants.setdefault(key, []).extend((ns, r) for r in rules)
    return grants


def _has(values: list[str] | None, wanted: str) -> bool:
    return bool(values) and ("*" in values or wanted in values)


def allows(grants: list[tuple[str, dict]], namespace: str, verb: str, resource: str, group: str = "") -> bool:
    for ns, rule in grants:
        if ns not in ("*", namespace):
            continue
        if rule.get("resourceNames"):
            continue  # a rule limited to named objects is the recommended narrow pattern, not a broad path
        groups = rule.get("apiGroups") or [""]
        if not (_has(rule.get("verbs"), verb) and _has(rule.get("resources"), resource) and ("*" in groups or group in groups)):
            continue
        return True
    return False


def analyse_subject(subject: str, grants: list[tuple[str, dict]], namespaces: list[str]) -> list[Path]:
    out: list[Path] = []
    for ns in namespaces:
        can = lambda v, r, g="": allows(grants, ns, v, r, g)  # noqa: E731
        if any(can(v, "secrets") for v in ("get", "list", "watch")):
            listing = can("list", "secrets") or can("watch", "secrets")
            out.append(Path(subject, ns, "SEC-001", "CRITICAL" if listing else "HIGH",
                            "can read Secrets" + (": list/watch returns every Secret value in the namespace" if listing else " by name"),
                            "grant get on named secrets (resourceNames) only; never list or watch"))
        if can("create", "pods"):
            out.append(Path(subject, ns, "SEC-002", "CRITICAL", "can create pods, so a pod can mount any Secret or service-account token in the namespace",
                            "restrict pod creation to CI identities; enforce Pod Security and admission policy"))
        if can("create", "pods/exec") or can("get", "pods/exec"):
            out.append(Path(subject, ns, "SEC-003", "HIGH", "pods/exec lets them run commands in a pod and read its env, mounted secrets and SA token",
                            "remove pods/exec from standing roles; use break-glass access with audit"))
        if can("create", "serviceaccounts/token"):
            out.append(Path(subject, ns, "SEC-004", "HIGH", "can mint tokens for any service account in the namespace, including powerful ones",
                            "limit with resourceNames"))
        if can("impersonate", "users") or can("impersonate", "groups") or can("impersonate", "serviceaccounts"):
            out.append(Path(subject, ns, "SEC-005", "CRITICAL", "impersonation lets them act as a more privileged identity",
                            "avoid impersonate; scope it to specific resourceNames"))
        if can("get", "nodes/proxy") or can("create", "nodes/proxy"):
            out.append(Path(subject, ns, "SEC-006", "HIGH", "nodes/proxy reaches the kubelet API of every node (pod lists, and run/exec on some setups)",
                            "remove it; monitoring should use scoped metrics endpoints"))
        if (can("escalate", "roles", "rbac.authorization.k8s.io") or can("bind", "roles", "rbac.authorization.k8s.io")
                or can("escalate", "clusterroles", "rbac.authorization.k8s.io") or can("bind", "clusterroles", "rbac.authorization.k8s.io")
                or can("create", "rolebindings", "rbac.authorization.k8s.io") or can("create", "clusterrolebindings", "rbac.authorization.k8s.io")):
            out.append(Path(subject, ns, "SEC-007", "CRITICAL", "can grant itself or others more permissions (escalate, bind, or create bindings)",
                            "only cluster admins should hold these verbs"))
        if any(can(v, r) for v in ("patch", "update") for r in WORKLOAD_KINDS_RES if r != "pods") or can("patch", "pods") or can("update", "pods"):
            out.append(Path(subject, ns, "SEC-010", "HIGH", "can edit workloads, so it can add a container or volume that exposes a Secret",
                            "limit edit rights; use GitOps with review"))
        if can("*", "*", "*"):
            out.append(Path(subject, ns, "SEC-008", "CRITICAL", "wildcard verbs and resources: effectively cluster-admin for this scope",
                            "replace with explicit verbs and resources"))
    return out


def analyse(docs: list[dict]) -> list[Path]:
    namespaces = sorted({d["metadata"]["namespace"] for d in docs if d["metadata"].get("namespace")} | {d["metadata"]["name"] for d in docs if d["kind"] == "Namespace"})
    result: list[Path] = []
    for subject, grants in build_grants(docs).items():
        found = analyse_subject(subject, grants, namespaces)
        # collapse identical findings across namespaces for cluster-wide grants
        seen: dict[str, Path] = {}
        for p in found:
            seen.setdefault(p.path_id, p)
        if any(ns == "*" for ns, _ in grants):
            result += [Path(p.subject, "*", p.path_id, p.severity, p.why, p.fix) for p in seen.values()]
        else:
            result += found
    order = {"CRITICAL": 0, "HIGH": 1}
    return sorted(result, key=lambda p: (order.get(p.severity, 2), p.subject, p.path_id))


def pod_paths(docs: list[dict]) -> list[str]:
    """Pods whose service account can reach secrets: compromise the app, get the secrets."""
    grants = build_grants(docs)
    risky = {s: {p.path_id for p in analyse_subject(s, g, sorted({d['metadata'].get('namespace', 'default') for d in docs if d['metadata'].get('namespace')}))} for s, g in grants.items()}
    out = []
    for d in docs:
        if d["kind"] != "Pod":
            continue
        ns = d["metadata"].get("namespace", "default")
        spec = d["spec"]
        sa = spec.get("serviceAccountName", "default")
        if spec.get("automountServiceAccountToken") is False:
            continue
        hits = {p.path_id for p in analyse_subject(f"sa:{ns}:{sa}", grants.get(f"sa:{ns}:{sa}", []) + grants.get("group:system:serviceaccounts", []) + grants.get(f"group:system:serviceaccounts:{ns}", []), [ns])}
        if hits:
            out.append(f"Pod/{ns}/{d['metadata']['name']} (sa {sa}) -> {sorted(hits)}")
    return out
