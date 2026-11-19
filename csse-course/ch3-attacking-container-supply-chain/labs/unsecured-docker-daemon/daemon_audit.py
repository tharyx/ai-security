"""Audit a Docker daemon.json against a subset of CIS Docker Benchmark ideas.

IDs here are this lab's own (DD-xxx). Each line names the benchmark idea; the exact CIS control numbers change
between benchmark versions, so look them up in your version ("verify at source").
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str


def tcp_hosts(cfg: dict) -> list[str]:
    return [h for h in cfg.get("hosts", []) if h.startswith("tcp://")]


def has_tls(cfg: dict) -> bool:
    return bool(cfg.get("tlsverify")) and all(cfg.get(k) for k in ("tlscacert", "tlscert", "tlskey"))


def audit(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    add = lambda r, s, m: out.append(Finding(r, s, m))  # noqa: E731
    tcp = tcp_hosts(cfg)
    if tcp and not has_tls(cfg):
        add("DD-001", "CRITICAL", f"daemon API on {tcp} without TLS client verification: anyone who can reach the port controls the host")
    for h in tcp:
        if h.endswith(":2375"):
            add("DD-002", "HIGH", f"{h}: 2375 is the conventional plaintext port (2376 is the TLS port)")
        if "0.0.0.0" in h:
            add("DD-003", "HIGH", f"{h}: bound to all interfaces; bind to a private address or use SSH tunnels")
    if cfg.get("icc", True):
        add("DD-004", "MEDIUM", "inter-container communication on the default bridge is allowed (set icc=false)")
    if not cfg.get("userns-remap"):
        add("DD-005", "MEDIUM", "user namespace remapping is off, so container root is host root (use userns-remap or rootless Docker)")
    if not cfg.get("no-new-privileges"):
        add("DD-006", "LOW", "no-new-privileges is not the daemon default")
    if not cfg.get("live-restore"):
        add("DD-007", "LOW", "live-restore is off: containers stop when the daemon restarts (availability)")
    if cfg.get("insecure-registries"):
        add("DD-008", "HIGH", f"insecure-registries {cfg['insecure-registries']}: images pulled without TLS verification")
    if cfg.get("log-driver") in (None, "none"):
        add("DD-009", "MEDIUM", "container logging is disabled or unset; you lose evidence")
    if cfg.get("userland-proxy", True):
        add("DD-010", "LOW", "userland-proxy is on (hairpin NAT is the safer option)")
    if cfg.get("experimental"):
        add("DD-011", "LOW", "experimental features are enabled in production")
    if cfg.get("seccomp-profile") == "unconfined":
        add("DD-012", "HIGH", "default seccomp profile is disabled daemon-wide")
    return sorted(out, key=lambda f: -SEVERITY[f.severity])


def socket_findings(mode: str, group: str) -> list[Finding]:
    """The Unix socket /var/run/docker.sock should be root:docker 0660. World access is root for everyone."""
    out = []
    if int(mode, 8) & 0o007:
        out.append(Finding("DD-013", "CRITICAL", f"docker.sock mode {mode} is accessible to every local user"))
    if group not in ("docker", "root"):
        out.append(Finding("DD-014", "MEDIUM", f"docker.sock group is '{group}'; membership equals root, keep the group tiny"))
    return out


def scan_listeners(ss_text: str) -> list[Finding]:
    """Look for the Docker API ports in `ss -ltnp` output."""
    out = []
    for line in ss_text.splitlines():
        m = re.search(r"(\S+):(2375|2376)\s", line)
        if m and m.group(1) not in ("127.0.0.1", "[::1]"):
            sev = "CRITICAL" if m.group(2) == "2375" else "MEDIUM"
            out.append(Finding("DD-020", sev, f"Docker API listening on {m.group(1)}:{m.group(2)}"))
    return out


class FakeDaemon:
    """A pretend daemon that answers `GET /version` the way the config says it would (no sockets)."""

    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg

    def get_version(self, *, tls_client_cert: bool = False) -> tuple[int, str]:
        if not tcp_hosts(self.cfg):
            return 0, "connection refused (no TCP listener)"
        if has_tls(self.cfg):
            return (200, "Docker version 27.x (SIMULATED)") if tls_client_cert else (0, "TLS handshake failed: client certificate required")
        return 200, "Docker version 27.x (SIMULATED): API answers anyone, including POST /containers/create"


def audit_file(path: str | Path) -> list[Finding]:
    return audit(json.loads(Path(path).read_text()))
