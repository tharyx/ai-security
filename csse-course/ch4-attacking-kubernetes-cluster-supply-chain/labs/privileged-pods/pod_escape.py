"""Find privileged pods and their escape paths, and classify pods by Pod Security Standard level.

Pod Security Standards (PSS) define three levels: privileged (no limits), baseline (blocks known escalations),
restricted (hardening best practice). Pod Security Admission (PSA) enforces them per namespace through labels.
PodSecurityPolicy (PSP) was removed in Kubernetes 1.25; PSA, ValidatingAdmissionPolicy, Kyverno or Gatekeeper replace it.

This lab implements a subset of the PSS checks (the ones in the official policy tables you should know) and
cross-checks with the module-06 manifest linter (k8s_policy.py). Verify exact rules at kubernetes.io.
"""
from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]

BASELINE_CAPS = {"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE",
                 "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}
RESTRICTED_VOLUMES = {"configMap", "csi", "downwardAPI", "emptyDir", "ephemeral", "persistentVolumeClaim", "projected", "secret"}
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def _load_k8s_policy():
    name = "csse4_k8s_policy"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO / "06-ai-devsecops/kubernetes/lab/k8s_policy.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


k8s_policy = _load_k8s_policy()


def pod_spec(doc: dict) -> dict:
    spec = doc.get("spec") or {}
    if doc["kind"] == "Pod":
        return spec
    if doc["kind"] == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def containers(spec: dict) -> list[dict]:
    return (spec.get("initContainers") or []) + (spec.get("containers") or []) + (spec.get("ephemeralContainers") or [])


def _sc(spec: dict, c: dict, key: str):
    csc, psc = c.get("securityContext") or {}, spec.get("securityContext") or {}
    return csc[key] if key in csc else psc.get(key)


def baseline_violations(spec: dict) -> list[str]:
    v = []
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(key):
            v.append(f"{key}=true")
    for vol in spec.get("volumes") or []:
        if "hostPath" in vol:
            v.append(f"hostPath volume {vol['hostPath'].get('path')}")
    for c in containers(spec):
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            v.append(f"container {c['name']} privileged")
        extra = set((sc.get("capabilities") or {}).get("add") or []) - BASELINE_CAPS
        if extra:
            v.append(f"container {c['name']} adds capabilities {sorted(extra)}")
        if any(p.get("hostPort") for p in c.get("ports") or []):
            v.append(f"container {c['name']} uses hostPort")
        if (_sc(spec, c, "seccompProfile") or {}).get("type") == "Unconfined":
            v.append(f"container {c['name']} seccomp Unconfined")
        if sc.get("procMount") not in (None, "Default"):
            v.append(f"container {c['name']} procMount {sc['procMount']}")
    return v


def restricted_violations(spec: dict) -> list[str]:
    v = []
    for vol in spec.get("volumes") or []:
        kinds = set(vol) - {"name"}
        if not kinds <= RESTRICTED_VOLUMES:
            v.append(f"volume type {sorted(kinds - RESTRICTED_VOLUMES)}")
    for c in containers(spec):
        if _sc(spec, c, "allowPrivilegeEscalation") is not False:
            v.append(f"container {c['name']} must set allowPrivilegeEscalation=false")
        if _sc(spec, c, "runAsNonRoot") is not True:
            v.append(f"container {c['name']} must run as non-root")
        if _sc(spec, c, "runAsUser") == 0:
            v.append(f"container {c['name']} runAsUser 0")
        caps = (c.get("securityContext") or {}).get("capabilities") or {}
        if "ALL" not in (caps.get("drop") or []):
            v.append(f"container {c['name']} must drop ALL capabilities")
        if set(caps.get("add") or []) - {"NET_BIND_SERVICE"}:
            v.append(f"container {c['name']} adds capabilities other than NET_BIND_SERVICE")
        if (_sc(spec, c, "seccompProfile") or {}).get("type") not in ("RuntimeDefault", "Localhost"):
            v.append(f"container {c['name']} needs seccompProfile RuntimeDefault or Localhost")
    return v


def pss_level(spec: dict) -> str:
    """The strictest standard the pod satisfies."""
    if baseline_violations(spec):
        return "privileged"
    return "baseline" if restricted_violations(spec) else "restricted"


@dataclass(frozen=True)
class Escape:
    kind: str
    why: str


def escape_paths(spec: dict) -> list[Escape]:
    out: list[Escape] = []
    privileged = any((c.get("securityContext") or {}).get("privileged") for c in containers(spec))
    caps = {x for c in containers(spec) for x in ((c.get("securityContext") or {}).get("capabilities") or {}).get("add", [])}
    if privileged:
        out.append(Escape("privileged", "all capabilities and host devices: the node disk and kernel are within reach"))
    for vol in spec.get("volumes") or []:
        if "hostPath" in vol:
            p = vol["hostPath"].get("path", "")
            if p in ("/", "/etc", "/var/lib/kubelet", "/var/run", "/run", "/proc", "/var/lib/docker") or p.endswith(("docker.sock", "containerd.sock", "crio.sock")):
                out.append(Escape("hostPath", f"mounts {p}: host files, kubelet credentials or the runtime socket"))
            else:
                out.append(Escape("hostPath-narrow", f"mounts {p}: review what an attacker could read or write there"))
    if spec.get("hostPID") and (privileged or {"SYS_PTRACE", "SYS_ADMIN"} & caps):
        out.append(Escape("hostPID+ptrace", "can inspect host processes and their /proc/<pid>/root"))
    elif spec.get("hostPID"):
        out.append(Escape("hostPID", "sees host process list and environment"))
    if spec.get("hostNetwork"):
        out.append(Escape("hostNetwork", "reaches node-local services (kubelet, metadata endpoints) and sees node traffic"))
    if "SYS_ADMIN" in caps and not privileged:
        out.append(Escape("SYS_ADMIN", "mount and namespace operations"))
    return out


def analyse_file(path: str | Path) -> dict[str, dict]:
    result = {}
    for d in yaml.safe_load_all(Path(path).read_text()):
        if d and d["kind"] in WORKLOADS:
            spec = pod_spec(d)
            result[f"{d['kind']}/{d['metadata']['name']}"] = {
                "level": pss_level(spec), "escapes": [e.kind for e in escape_paths(spec)],
                "baseline": baseline_violations(spec), "restricted": restricted_violations(spec)}
    return result


def lint06(path: str | Path) -> set[str]:
    """Rule IDs from the module-06 linter, to show the two views agree on the dangerous settings."""
    return {f.rule_id for f in k8s_policy.check(k8s_policy.load_docs(path))}
