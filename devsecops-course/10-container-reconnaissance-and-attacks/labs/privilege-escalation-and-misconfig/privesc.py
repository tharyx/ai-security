"""Privilege escalation methods in Docker and security misconfigurations, analysed from a host profile.

The core idea: the Docker daemon runs as root and anyone who can talk to it can ask it to do root things.
So "can use docker" == "is root". This lab finds those equivalences and lists the misconfigurations around them.
Analysis only: nothing is executed.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Chain:
    who: str
    severity: str
    chain: tuple[str, ...]
    fix: str


def analyze_host(host: dict) -> list[Chain]:
    d = host["daemon"]
    sock = host["socket"]
    rootful = not d.get("rootless")
    out: list[Chain] = []
    for u in host["users"]:
        if "docker" in u["groups"]:
            if rootful:
                sev = "CRITICAL" if not d.get("userns_remap") else "HIGH"
                chain = [f"{u['name']} is in the 'docker' group", f"group has {sock['mode']} access to {sock['path']}",
                         "the daemon runs as root on the host", "a container can be started with the host file system mounted"]
                chain.append("result: root-equivalent on the host" if not d.get("userns_remap") else
                             "result: remapped UIDs limit some file writes, but host mounts and devices still expose a lot")
                out.append(Chain(u["name"], sev, tuple(chain), "Remove the user from 'docker'; use rootless Docker/Podman, or sudo with an audited, narrow wrapper."))
            else:
                out.append(Chain(u["name"], "LOW", (f"{u['name']} uses a ROOTLESS daemon", "the daemon and containers run as that same unprivileged user",
                                                     "result: no gain beyond the user's own rights"), "Rootless is the fix: keep it."))
        if u.get("sudo_nopasswd") and "ALL" in u.get("sudo_commands", []):
            out.append(Chain(u["name"], "HIGH", (f"{u['name']} has passwordless sudo for ALL", "result: root without any container trick"), "Require a password, limit commands."))
    if sock["mode"] not in ("660", "0660") or sock["group"] != "docker":
        out.append(Chain("any local user", "CRITICAL" if sock["mode"].endswith(("6", "7")) else "MEDIUM",
                         (f"{sock['path']} has mode {sock['mode']} group {sock['group']}", "other users can reach the daemon API", "result: root-equivalent"),
                         "chmod 660, group docker (or a dedicated group), owner root."))
    for c in host.get("containers", []):
        for chain in container_misconfigs(c):
            out.append(chain)
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return sorted(out, key=lambda c: (order.index(c.severity), c.who))


def container_misconfigs(c: dict) -> list[Chain]:
    out = []
    n = c["name"]
    if c.get("user", "root") in ("root", "0") and c.get("writable_host_mounts"):
        out.append(Chain(n, "HIGH", (f"{n} runs as root", f"it has a writable host mount {c['writable_host_mounts'][0]}",
                                      "files it writes are owned by host root", "result: can plant a SetUID file or edit config on the host"),
                         "Run as a non-root UID, mount read-only, or enable userns-remap."))
    if c.get("setuid_in_image") and not c.get("no_new_privileges"):
        out.append(Chain(n, "MEDIUM", (f"{n} image contains SetUID binaries", "no-new-privileges is not set", "result: easier local privilege escalation inside the container"),
                         "--security-opt no-new-privileges and strip SetUID bits."))
    if c.get("env_secrets"):
        out.append(Chain(n, "MEDIUM", (f"{n} has secrets in env: {', '.join(c['env_secrets'])}", "docker inspect (needs docker access) shows them", "result: credential theft"),
                         "Use secrets mounted as files from a secret manager."))
    return out


def misconfiguration_checklist(host: dict) -> list[str]:
    d = host["daemon"]
    out = []
    if not d.get("userns_remap") and not d.get("rootless"):
        out.append("rootful daemon with no user namespace remapping")
    if not d.get("tls_on_tcp", True):
        out.append("TCP endpoint without TLS")
    if d.get("log_driver") == "none":
        out.append("logging disabled: no evidence after an incident")
    if not d.get("content_trust_alternative"):
        out.append("no image signature verification (cosign/Notation) in the pipeline")
    return out
