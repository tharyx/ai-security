"""A simulated kubelet API and a KubeletConfiguration auditor (in-process; no sockets, nothing is executed).

The real kubelet listens on 10250 (HTTPS) and, if enabled, 10255 (read-only HTTP). With anonymous-auth on and
authorization-mode AlwaysAllow, anyone who can reach the port can list pods and run commands in containers.
`/run` here only returns a string saying what WOULD have run.
"""
from __future__ import annotations

from dataclasses import dataclass

import yaml

# How the kubelet maps request paths to the SubjectAccessReview resource it checks (concept; verify in docs).
SUBRESOURCE = {"/metrics": "nodes/metrics", "/stats": "nodes/stats", "/logs": "nodes/log", "/spec": "nodes/spec"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str


class Kubelet:
    def __init__(self, config: dict, pods: list[dict], allowed: dict[str, set[str]] | None = None) -> None:
        self.cfg, self.pods = config, pods
        self.allowed = allowed or {}   # user -> set of RBAC subresources, e.g. {"monitoring": {"nodes/metrics"}}

    def handle(self, method: str, path: str, *, port: int = 10250, user: str | None = None, body: dict | None = None) -> tuple[int, object]:
        cfg = self.cfg
        if port == 10255:
            if cfg.get("readOnlyPort", 0) == 0:
                return 0, "connection refused (read-only port disabled)"
            if method == "GET" and path in ("/pods", "/metrics", "/healthz"):
                return 200, self._pods() if path == "/pods" else "ok"
            return 404, "not found on the read-only port"
        if user is None:
            if not cfg.get("authentication", {}).get("anonymous", {}).get("enabled", False):
                return 401, "Unauthorized"
            user = "system:anonymous"
        if path == "/healthz":
            return 200, "ok"
        needed = SUBRESOURCE.get(path, "nodes/proxy")
        if cfg.get("authorization", {}).get("mode", "Webhook") == "Webhook" and needed not in self.allowed.get(user, set()):
            return 403, f"Forbidden: user {user} cannot access {needed}"
        if method == "GET" and path == "/pods":
            return 200, self._pods()
        if method == "GET" and path in SUBRESOURCE:
            return 200, "SIMULATED node data"
        if method == "POST" and path.startswith("/run/"):
            parts = path.split("/")[2:]
            if len(parts) != 3:
                return 404, "expected /run/<namespace>/<pod>/<container>"
            cmd = (body or {}).get("cmd", "")
            return 200, f"SIMULATED run of '{cmd}' in {'/'.join(parts)} (nothing was executed)"
        return 404, "not found"

    def _pods(self) -> list[str]:
        return [f"{p['namespace']}/{p['name']} ({p['image']})" for p in self.pods]


def audit_config(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    if cfg.get("authentication", {}).get("anonymous", {}).get("enabled", False):
        out.append(Finding("KL-001", "CRITICAL", "authentication.anonymous.enabled is true"))
    if cfg.get("authorization", {}).get("mode", "Webhook") == "AlwaysAllow":
        out.append(Finding("KL-002", "CRITICAL", "authorization.mode is AlwaysAllow: every authenticated (or anonymous) caller may do everything"))
    if cfg.get("readOnlyPort", 0) != 0:
        out.append(Finding("KL-003", "HIGH", f"readOnlyPort {cfg['readOnlyPort']} serves pod data without authentication; set 0"))
    if not cfg.get("authentication", {}).get("x509", {}).get("clientCAFile"):
        out.append(Finding("KL-004", "MEDIUM", "no x509 clientCAFile: the API server's client certificate cannot be verified"))
    if not cfg.get("authentication", {}).get("webhook", {}).get("enabled", True):
        out.append(Finding("KL-005", "HIGH", "webhook authentication is disabled: bearer tokens are not validated against the API server"))
    if not cfg.get("protectKernelDefaults", False):
        out.append(Finding("KL-006", "LOW", "protectKernelDefaults is false"))
    if not cfg.get("rotateCertificates", False):
        out.append(Finding("KL-007", "LOW", "client certificate rotation is off"))
    return out


def load_config(text: str) -> dict:
    cfg = yaml.safe_load(text)
    if cfg.get("kind") != "KubeletConfiguration":
        raise ValueError("not a KubeletConfiguration")
    return cfg
