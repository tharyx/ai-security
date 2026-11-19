"""Detecting reverse shells in simulated telemetry (no attack code anywhere).

A reverse shell is the post-exploitation step where a compromised server process
starts a shell whose input/output is connected to an outbound network socket that
the attacker controls. This lab never builds one. It reads STRUCTURED events, the
kind an EDR, auditd, Falco or Sysmon would emit, and flags the patterns:

  R1 lineage:   a shell or interpreter spawned by a server process (web app, API runtime)
  R2 socket fd: a shell whose stdin/stdout is a network socket
  R3 egress:    an outbound connection from a shell to a destination not on the egress allowlist
  R4 indicator: command-line indicator tokens (e.g. "/dev/tcp/", netcat-family binary with -e)
  R5 image:     prevention check: a container image that ships a shell at all

Fixtures: fixtures/process_events.json and fixtures/network_flows.json (fictional,
documentation IP ranges, redacted command lines).
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

SHELLS = {"sh", "bash", "dash", "zsh", "ash", "cmd.exe", "powershell.exe", "pwsh"}
INTERPRETERS = {"python3", "perl", "ruby", "php", "node"}
SERVER_PARENTS = {"gunicorn", "uwsgi", "java", "node", "php-fpm", "nginx", "httpd", "python3 app.py", "dotnet"}
NETCAT_FAMILY = {"nc", "ncat", "netcat", "socat"}
INDICATOR_TOKENS = ("/dev/tcp/", "/dev/udp/", "pty.spawn")


def load(path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def in_allowlist(dst: str, allowlist: list[str]) -> bool:
    ip = ipaddress.ip_address(dst)
    return any(ip in ipaddress.ip_network(net) for net in allowlist)


def detect(processes: list[dict], flows: list[dict], egress_allowlist: list[str]) -> list[dict]:
    alerts = []
    by_pid = {p["pid"]: p for p in processes}
    for p in processes:
        rules = []
        exe = p["exe"]
        parent = by_pid.get(p.get("ppid"), {}).get("exe", p.get("parent_exe", ""))
        if (exe in SHELLS or exe in INTERPRETERS) and parent in SERVER_PARENTS:
            rules.append("R1 shell/interpreter spawned by server process " + parent)
        if exe in SHELLS and (p.get("stdin_type") == "socket" or p.get("stdout_type") == "socket"):
            rules.append("R2 shell with stdin/stdout bound to a network socket")
        cmd = p.get("cmdline", "")
        args = cmd.split()
        if any(tok in cmd for tok in INDICATOR_TOKENS) or (exe in NETCAT_FAMILY and ("-e" in args or "-c" in args)):
            rules.append("R4 command-line indicator")
        for f in flows:
            if f["pid"] == p["pid"] and f["direction"] == "outbound" and exe in SHELLS | INTERPRETERS | NETCAT_FAMILY \
                    and not in_allowlist(f["dst"], egress_allowlist):
                rules.append(f"R3 outbound {f['dst']}:{f['dport']} not in egress allowlist")
        if rules:
            sev = "CRITICAL" if len(rules) >= 2 else "HIGH" if rules[0].startswith(("R2", "R4")) else "MEDIUM"
            alerts.append({"pid": p["pid"], "host": p["host"], "exe": exe, "parent": parent, "severity": sev,
                           "rules": rules})
    return alerts


def egress_blocked(flows: list[dict], egress_allowlist: list[str]) -> list[dict]:
    """Prevention view: which outbound flows a default-deny egress policy would have dropped."""
    return [f for f in flows if f["direction"] == "outbound" and not in_allowlist(f["dst"], egress_allowlist)]


def image_findings(manifest: dict) -> list[str]:
    """R5: images should not need a shell or network tools at runtime (distroless / scratch)."""
    found = [f for f in manifest.get("files", []) if f.rsplit("/", 1)[-1] in SHELLS | NETCAT_FAMILY]
    out = [f"R5 image {manifest['image']} ships {f}" for f in found]
    if manifest.get("user", "root") == "root":
        out.append(f"R5 image {manifest['image']} runs as root")
    return out
