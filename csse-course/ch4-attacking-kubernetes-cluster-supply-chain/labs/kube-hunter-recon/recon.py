"""Cluster recon from an endpoint inventory (simulated; no scanning, no network).

LEGACY NOTE. kube-hunter (Aqua Security) is no longer actively developed, and Aqua points users to Trivy
(`trivy k8s`) for cluster scanning. The recon *ideas* (which ports are open, what answers anonymously) are still the
right questions, so this lab keeps them. For real work use Trivy, Kubescape and CIS kube-bench.

Input: a JSON inventory shaped like what a scan would learn: {host, port, service, anonymous: {path: status}}.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

LEGACY_BANNER = ("kube-hunter is legacy (no longer actively developed). Use `trivy k8s` or Kubescape for real scans; "
                 "this report keeps its recon ideas.")

# Known Kubernetes component ports.
KNOWN_PORTS = {6443: "kube-apiserver (secure)", 8080: "kube-apiserver (insecure, removed in modern versions)", 10250: "kubelet API",
               10255: "kubelet read-only port", 2379: "etcd client", 2380: "etcd peer", 10257: "kube-controller-manager",
               10259: "kube-scheduler", 8443: "dashboard or alt API", 30000: "NodePort range start"}

MODERN_TOOLS = {
    "API": "Kubescape / `trivy k8s` for config; kube-bench for CIS checks on API server flags",
    "KUBELET": "kube-bench (kubelet section); verify KubeletConfiguration",
    "ETCD": "kube-bench; network policy and firewall rules; encryption at rest",
    "DASHBOARD": "Kubescape; check Service type and auth",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    target: str
    message: str
    category: str


def load(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text())["endpoints"]


def analyse(endpoints: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for e in endpoints:
        t = f"{e['host']}:{e['port']}"
        anon = e.get("anonymous", {})
        svc = e["service"]
        if svc == "kube-apiserver":
            if anon.get("/api/v1/namespaces") == 200 or anon.get("/api/v1/secrets") == 200:
                out.append(Finding("REC-001", "CRITICAL", t, "API server answers anonymous requests to read cluster objects", "API"))
            elif anon.get("/version") == 200:
                out.append(Finding("REC-002", "LOW", t, "anonymous users can read /version (normal default, but reveals the version)", "API"))
            if e["port"] == 8080:
                out.append(Finding("REC-003", "CRITICAL", t, "insecure port: no authentication, no authorization", "API"))
        elif svc == "kubelet":
            if anon.get("/pods") == 200:
                out.append(Finding("REC-010", "CRITICAL", t, "kubelet lists pods to anonymous callers (anonymous-auth enabled and authorization not enforced)", "KUBELET"))
            if anon.get("/run") in (200, 405):
                out.append(Finding("REC-011", "CRITICAL", t, "kubelet exposes /run: command execution in containers is reachable", "KUBELET"))
            if e["port"] == 10255 and anon.get("/pods") == 200:
                out.append(Finding("REC-012", "HIGH", t, "read-only kubelet port 10255 is open (should be disabled: readOnlyPort 0)", "KUBELET"))
        elif svc == "etcd":
            if anon.get("/version") == 200 or anon.get("/v2/keys") == 200:
                out.append(Finding("REC-020", "CRITICAL", t, "etcd answers without a client certificate: all cluster state incl. Secrets is readable", "ETCD"))
        elif svc == "dashboard":
            if anon.get("/") == 200 and not e.get("auth_required", True):
                out.append(Finding("REC-030", "CRITICAL", t, "dashboard is exposed without authentication", "DASHBOARD"))
            elif e.get("exposed_externally"):
                out.append(Finding("REC-031", "HIGH", t, "dashboard is reachable from outside the cluster", "DASHBOARD"))
        if e["port"] in (2379, 2380, 10250, 10255) and e.get("public"):
            out.append(Finding("REC-040", "HIGH", t, f"{KNOWN_PORTS[e['port']]} is reachable from a public address", "NETWORK"))
    return sorted(out, key=lambda f: ("CRITICAL HIGH MEDIUM LOW".split().index(f.severity), f.rule_id))


def report(endpoints: list[dict]) -> str:
    lines = [LEGACY_BANNER, "", f"Endpoints inventoried: {len(endpoints)}"]
    for e in endpoints:
        lines.append(f"  {e['host']}:{e['port']:<6} {KNOWN_PORTS.get(e['port'], 'unknown'):38} public={e.get('public', False)}")
    findings = analyse(endpoints)
    lines += ["", f"Findings: {len(findings)}"]
    for f in findings:
        lines.append(f"  [{f.severity:8}] {f.rule_id} {f.target}: {f.message}")
    cats = sorted({f.category for f in findings if f.category in MODERN_TOOLS})
    if cats:
        lines += ["", "Modern follow-up:"] + [f"  {c}: {MODERN_TOOLS[c]}" for c in cats]
    return "\n".join(lines)
