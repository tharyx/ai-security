"""Check Kubernetes manifests for a model-serving workload before they reach the cluster.

    python k8s_policy.py manifests/*.yaml [--disable K8S-017]

It reads every YAML document (yaml.safe_load_all - never yaml.load on untrusted input),
groups objects by namespace, and runs rules about four things:

    pod hardening      securityContext, host access, image pinning, resource limits
    secrets/identity   no literal secrets, no static cloud keys, no automounted API token
    isolation          Pod Security labels, default-deny NetworkPolicy, egress control,
                       no public Service, dedicated GPU node pool
    authorization      no cluster-admin / wildcard RBAC

This is the CI ("shift-left") half of the control. The cluster-side half is admission
control (Pod Security Admission, ValidatingAdmissionPolicy, Kyverno or Gatekeeper),
which also blocks anything that never went through CI. Real tools: kube-linter, kubescape,
Trivy config, Checkov.
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
WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
STATIC_CLOUD_CREDS = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
                      "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH"}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
GPU_RESOURCES = ("nvidia.com/gpu", "amd.com/gpu")
INTERNAL_LB_ANNOTATIONS = {
    "service.beta.kubernetes.io/aws-load-balancer-internal",
    "networking.gke.io/load-balancer-type",
    "service.beta.kubernetes.io/azure-load-balancer-internal",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    obj: str      # Kind/namespace/name
    message: str


@dataclass
class Workload:
    ref: str
    namespace: str
    pod: dict           # the pod spec

    def containers(self) -> list[dict]:
        return (self.pod.get("initContainers") or []) + (self.pod.get("containers") or [])


class Bundle:
    """All objects from a set of manifests."""

    def __init__(self, docs: list[dict]) -> None:
        self.docs = [d for d in docs if isinstance(d, dict) and d.get("kind")]
        self.workloads: list[Workload] = []
        for d in self.docs:
            if d["kind"] in WORKLOAD_KINDS:
                self.workloads.append(Workload(ref(d), namespace(d), pod_spec(d)))

    def of_kind(self, kind: str) -> list[dict]:
        return [d for d in self.docs if d["kind"] == kind]

    def namespaces_in_use(self) -> set[str]:
        return {w.namespace for w in self.workloads}


def namespace(d: dict) -> str:
    return (d.get("metadata") or {}).get("namespace") or "default"


def ref(d: dict) -> str:
    meta = d.get("metadata") or {}
    ns = f"{meta['namespace']}/" if meta.get("namespace") else ""
    return f"{d['kind']}/{ns}{meta.get('name', '?')}"


def pod_spec(d: dict) -> dict:
    spec = d.get("spec") or {}
    if d["kind"] == "Pod":
        return spec
    if d["kind"] == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    return ((spec.get("template") or {}).get("spec") or {})


def effective(w: Workload, c: dict, key: str):
    """Container securityContext wins over the pod securityContext (as in Kubernetes)."""
    csc, psc = c.get("securityContext") or {}, w.pod.get("securityContext") or {}
    return csc[key] if key in csc else psc.get(key)


# --------------------------------------------------------------------------- rules

Rule = Callable[[Bundle], Iterator[tuple[str, str]]]
RULES: dict[str, tuple[str, str, Rule]] = {}


def rule(rule_id: str, severity: str, title: str) -> Callable[[Rule], Rule]:
    def register(fn: Rule) -> Rule:
        RULES[rule_id] = (severity, title, fn)
        return fn
    return register


@rule("K8S-001", "HIGH", "Privileged container or privilege escalation allowed")
def privileged(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            sc = c.get("securityContext") or {}
            if sc.get("privileged") is True:
                yield w.ref, f"container '{c['name']}' is privileged (root on the node)"
            elif sc.get("allowPrivilegeEscalation") is not False:
                yield w.ref, f"container '{c['name']}' does not set allowPrivilegeEscalation: false"


@rule("K8S-002", "HIGH", "Container may run as root")
def root_user(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            if effective(w, c, "runAsUser") == 0 or effective(w, c, "runAsNonRoot") is not True:
                yield w.ref, f"container '{c['name']}' can run as UID 0 (set runAsNonRoot: true and a UID)"


@rule("K8S-003", "MEDIUM", "Root filesystem is writable")
def writable_rootfs(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            if (c.get("securityContext") or {}).get("readOnlyRootFilesystem") is not True:
                yield w.ref, f"container '{c['name']}': an attacker can drop tools or modify code on disk"


@rule("K8S-004", "MEDIUM", "Linux capabilities not dropped")
def capabilities(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            caps = (c.get("securityContext") or {}).get("capabilities") or {}
            if "ALL" not in (caps.get("drop") or []):
                yield w.ref, f"container '{c['name']}' keeps default capabilities (drop: [ALL])"
            added = DANGEROUS_CAPS & set(caps.get("add") or [])
            if added:
                yield w.ref, f"container '{c['name']}' adds {sorted(added)}"


@rule("K8S-005", "MEDIUM", "No seccomp profile")
def seccomp(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            profile = effective(w, c, "seccompProfile") or {}
            if profile.get("type") not in {"RuntimeDefault", "Localhost"}:
                yield w.ref, f"container '{c['name']}' runs Unconfined (set seccompProfile RuntimeDefault)"


@rule("K8S-006", "CRITICAL", "Host namespaces or hostPath volumes")
def host_access(b: Bundle):
    for w in b.workloads:
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if w.pod.get(key) is True:
                yield w.ref, f"{key}: true breaks the pod's isolation from the node"
        for v in w.pod.get("volumes") or []:
            if "hostPath" in v:
                yield w.ref, f"volume '{v['name']}' mounts host path {v['hostPath'].get('path')}"


@rule("K8S-007", "MEDIUM", "Image not pinned by digest")
def image_digest(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            if "@sha256:" not in c.get("image", ""):
                yield w.ref, f"image '{c.get('image')}' can change without a manifest change"


@rule("K8S-008", "MEDIUM", "Missing CPU/memory limits")
def limits(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            lim = (c.get("resources") or {}).get("limits") or {}
            missing = [r for r in ("cpu", "memory") if r not in lim]
            if missing:
                yield w.ref, f"container '{c['name']}' has no {'/'.join(missing)} limit (one bad prompt can starve the node)"


@rule("K8S-009", "CRITICAL", "Secret value written in the manifest")
def literal_secrets(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            for e in c.get("env") or []:
                if SECRET_NAME.search(e.get("name", "")) and e.get("value"):
                    yield w.ref, f"env {e['name']} has a literal value; it is now in Git and in every copy of this file"


@rule("K8S-010", "HIGH", "Static cloud credentials instead of workload identity")
def static_cloud_creds(b: Bundle):
    for w in b.workloads:
        for c in w.containers():
            names = {e.get("name") for e in c.get("env") or []}
            for name in sorted(names & STATIC_CLOUD_CREDS):
                yield w.ref, f"env {name}: long-lived cloud key; use IRSA / EKS Pod Identity / GKE or AKS Workload Identity"


@rule("K8S-011", "MEDIUM", "Kubernetes API token automounted")
def automount(b: Bundle):
    sa_setting = {(namespace(sa), sa["metadata"]["name"]): sa.get("automountServiceAccountToken")
                  for sa in b.of_kind("ServiceAccount")}
    for w in b.workloads:
        pod_value = w.pod.get("automountServiceAccountToken")
        sa_value = sa_setting.get((w.namespace, w.pod.get("serviceAccountName", "default")))
        if pod_value is not False and not (pod_value is None and sa_value is False):
            yield w.ref, "a stolen pod gets a Kubernetes API token for free"


@rule("K8S-012", "HIGH", "Namespace does not enforce Pod Security 'restricted'")
def pod_security(b: Bundle):
    declared = {d["metadata"]["name"]: (d["metadata"].get("labels") or {}) for d in b.of_kind("Namespace")}
    for ns in sorted(b.namespaces_in_use()):
        if ns not in declared:
            yield f"Namespace/{ns}", "namespace is not declared in these manifests; cannot verify its Pod Security level"
        elif declared[ns].get("pod-security.kubernetes.io/enforce") != "restricted":
            yield f"Namespace/{ns}", "label pod-security.kubernetes.io/enforce: restricted is missing"


def is_default_deny(np: dict) -> bool:
    spec = np.get("spec") or {}
    types = set(spec.get("policyTypes") or [])
    return (spec.get("podSelector") in ({}, None) and {"Ingress", "Egress"} <= types
            and not spec.get("ingress") and not spec.get("egress"))


@rule("K8S-013", "HIGH", "No default-deny NetworkPolicy")
def default_deny(b: Bundle):
    for ns in sorted(b.namespaces_in_use()):
        if not any(is_default_deny(np) for np in b.of_kind("NetworkPolicy") if namespace(np) == ns):
            yield f"Namespace/{ns}", "every pod can talk to anything and be reached from anywhere"


@rule("K8S-014", "HIGH", "NetworkPolicy allows egress to the internet")
def open_egress(b: Bundle):
    for np in b.of_kind("NetworkPolicy"):
        for e in (np.get("spec") or {}).get("egress") or []:
            peers = e.get("to")
            if not peers:
                yield ref(np), "egress rule with no 'to' allows every destination"
            for peer in peers or []:
                if (peer.get("ipBlock") or {}).get("cidr") in {"0.0.0.0/0", "::/0"}:
                    yield ref(np), "egress to 0.0.0.0/0 lets a hijacked model server reach any host"


@rule("K8S-015", "HIGH", "Model server exposed outside the cluster")
def public_service(b: Bundle):
    for svc in b.of_kind("Service"):
        spec, notes = svc.get("spec") or {}, (svc.get("metadata") or {}).get("annotations") or {}
        if spec.get("type") == "NodePort":
            yield ref(svc), "NodePort opens the port on every node"
        if spec.get("type") == "LoadBalancer" and not INTERNAL_LB_ANNOTATIONS & set(notes):
            yield ref(svc), "public LoadBalancer: put the model behind an authenticated gateway instead"


@rule("K8S-016", "CRITICAL", "Over-privileged RBAC")
def rbac(b: Bundle):
    for binding in b.of_kind("ClusterRoleBinding") + b.of_kind("RoleBinding"):
        if (binding.get("roleRef") or {}).get("name") in {"cluster-admin", "admin"}:
            yield ref(binding), f"binds {binding['roleRef']['name']} to {[s.get('name') for s in binding.get('subjects') or []]}"
    for role in b.of_kind("ClusterRole") + b.of_kind("Role"):
        for r in role.get("rules") or []:
            if "*" in (r.get("verbs") or []) or "*" in (r.get("resources") or []):
                yield ref(role), "wildcard verbs or resources"
            elif "secrets" in (r.get("resources") or []) and {"get", "list", "watch"} & set(r.get("verbs") or []):
                yield ref(role), "can read Secrets"


@rule("K8S-017", "MEDIUM", "GPU workload not isolated on a dedicated node pool")
def gpu_isolation(b: Bundle):
    for w in b.workloads:
        wants_gpu = any(any(g in ((c.get("resources") or {}).get("limits") or {}) for g in GPU_RESOURCES)
                        for c in w.containers())
        if not wants_gpu:
            continue
        pinned = bool(w.pod.get("nodeSelector")) or bool((w.pod.get("affinity") or {}).get("nodeAffinity"))
        tolerates = any(t.get("key") in GPU_RESOURCES for t in w.pod.get("tolerations") or [])
        if not (pinned and tolerates):
            yield w.ref, "GPU pods should run only on a tainted, dedicated GPU pool (nodeSelector + toleration)"


# --------------------------------------------------------------------------- engine

def load_docs(*paths: str | Path) -> list[dict]:
    docs: list[dict] = []
    for p in paths:
        docs += [d for d in yaml.safe_load_all(Path(p).read_text(encoding="utf-8")) if d]
    return docs


def check(docs: list[dict], *, disabled: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    bundle = Bundle(docs)
    findings = []
    for rule_id, (severity, _title, fn) in sorted(RULES.items()):
        if rule_id not in disabled:
            findings += [Finding(rule_id, severity, obj, msg) for obj, msg in fn(bundle)]
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Kubernetes manifests for a model-serving workload.")
    parser.add_argument("manifests", nargs="+")
    parser.add_argument("--disable", action="append", default=[])
    parser.add_argument("--fail-on", default="HIGH", choices=list(SEVERITY))
    args = parser.parse_args(argv)
    findings = check(load_docs(*args.manifests), disabled=set(args.disable))
    for f in findings:
        print(f"{f.severity:8} {f.rule_id}  {f.obj}: {f.message}")
    failed = any(SEVERITY[f.severity] >= SEVERITY[args.fail_on] for f in findings)
    print(f"\n{'FAIL' if failed else 'PASS'}: {len(findings)} finding(s), fail-on={args.fail_on}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
