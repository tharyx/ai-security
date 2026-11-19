"""Turn the output of docker ps / inspect / info / network ls / volume ls (JSON fixtures) into an inventory
with a per-container risk score. Offline: the fixtures mirror real `docker ... --format json` / `inspect` fields.

Recon question list: what runs, as whom, with which privileges, mounts, ports, networks and secrets?
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DANGEROUS_CAPS = {"SYS_ADMIN": 25, "SYS_PTRACE": 20, "DAC_READ_SEARCH": 20, "SYS_MODULE": 30, "NET_ADMIN": 8, "NET_RAW": 4, "ALL": 30}
SENSITIVE = ("/var/run/docker.sock", "/run/docker.sock", "/etc", "/root", "/proc", "/sys", "/var/lib/docker")
SECRET_KEY = re.compile(r"(PASS(WORD)?|SECRET|TOKEN|API_?KEY|PRIVATE)", re.I)


def load(folder: str) -> dict:
    d = Path(folder)
    return {n: json.loads((d / f"{n}.json").read_text(encoding="utf-8")) for n in ("docker_ps", "inspect", "info", "network_ls", "volume_ls")}


@dataclass
class Item:
    name: str
    image: str
    status: str
    user: str
    ports: str
    networks: str
    score: int = 0
    risks: list[str] = field(default_factory=list)
    secret_env_names: list[str] = field(default_factory=list)

    @property
    def level(self) -> str:
        return "CRITICAL" if self.score >= 50 else "HIGH" if self.score >= 25 else "MEDIUM" if self.score >= 10 else "LOW"


def _add(it: Item, pts: int, msg: str) -> None:
    it.score += pts
    it.risks.append(msg)


def inventory(data: dict) -> list[Item]:
    by_id = {c["ID"]: c for c in data["docker_ps"]}
    items = []
    for doc in data["inspect"]:
        ps = by_id.get(doc["Id"][:12], {})
        cfg, hc = doc["Config"], doc["HostConfig"]
        it = Item(doc["Name"].lstrip("/"), cfg["Image"], ps.get("Status", "?"), cfg.get("User") or "root(default)", ps.get("Ports", ""), ps.get("Networks", ""))
        if hc.get("Privileged"):
            _add(it, 40, "privileged")
        for cap in hc.get("CapAdd") or []:
            if cap in DANGEROUS_CAPS:
                _add(it, DANGEROUS_CAPS[cap], f"cap_add {cap}")
        for b in hc.get("Binds") or []:
            src = b.split(":")[0]
            if src == "/" or any(src == s or src.startswith(s + "/") for s in SENSITIVE):
                _add(it, 35 if "docker.sock" in src or src == "/" else 15, f"sensitive bind mount {src}")
        if hc.get("NetworkMode") == "host":
            _add(it, 15, "host network")
        if hc.get("PidMode") == "host":
            _add(it, 20, "host PID namespace")
        if any(o in ("seccomp=unconfined", "apparmor=unconfined") for o in hc.get("SecurityOpt") or []):
            _add(it, 15, "seccomp/apparmor disabled")
        if it.user in ("root(default)", "root", "0"):
            _add(it, 5, "runs as root")
        if not hc.get("Memory"):
            _add(it, 3, "no memory limit")
        if not hc.get("PidsLimit"):
            _add(it, 2, "no pids limit")
        if cfg["Image"].endswith(":latest"):
            _add(it, 3, "image tag :latest")
        for e in cfg.get("Env") or []:
            k, _, v = e.partition("=")
            if SECRET_KEY.search(k) and v and not k.endswith("_FILE"):
                it.secret_env_names.append(k)
                _add(it, 8, f"secret in env {k}")
        if "0.0.0.0:" in it.ports:
            _add(it, 5, "port published on all interfaces")
        items.append(it)
    return sorted(items, key=lambda i: -i.score)


def host_findings(data: dict) -> list[str]:
    out = []
    info = data["info"]
    sec = " ".join(info.get("SecurityOptions", []))
    if "seccomp" not in sec:
        out.append("daemon has no default seccomp profile")
    if "rootless" not in sec and "userns" not in sec:
        out.append("daemon runs rootful without user namespace remapping")
    if not info.get("LiveRestoreEnabled"):
        out.append("live-restore disabled: daemon restart stops all containers")
    for name, conf in info.get("RegistryConfig", {}).get("IndexConfigs", {}).items():
        if not conf.get("Secure", True):
            out.append(f"insecure registry configured: {name}")
    for net in data["network_ls"]:
        if net["Driver"] == "bridge" and net["Options"].get("com.docker.network.bridge.enable_icc") == "true" and len(net["Containers"]) > 1:
            out.append(f"network '{net['Name']}': inter-container communication on with {len(net['Containers'])} containers")
    dangling = [v["Name"][:12] for v in data["volume_ls"] if not v["UsedBy"]]
    if dangling:
        out.append(f"{len(dangling)} unused volumes may hold old data: {', '.join(dangling)}")
    return out
