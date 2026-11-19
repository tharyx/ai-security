"""Docker host (daemon) and kernel attack surface, analysed offline.

Four analyses:
1. daemon.json: unauthenticated API, insecure TCP endpoint (no TLS), no user remapping.
2. flat networks: containers on the default bridge can all reach each other.
3. denial of service: no memory / pids / cpu limits; a fork-bomb CONCEPT as pure arithmetic (nothing is forked).
4. kernel exploits: containers share the host kernel; map the host kernel version to a FIXTURE vulnerability list.
"""
from __future__ import annotations

import re


# ---------- 1. daemon configuration ----------
def audit_daemon(cfg: dict) -> list[tuple[str, str]]:
    out = []
    hosts = cfg.get("hosts", ["unix:///var/run/docker.sock"])
    tls = cfg.get("tlsverify", False) and cfg.get("tlscert") and cfg.get("tlskey") and cfg.get("tlscacert")
    for h in hosts:
        m = re.match(r"tcp://([^:]+):(\d+)", h)
        if not m:
            continue
        host, port = m.groups()
        public = host in ("0.0.0.0", "::", "")
        if not tls:
            out.append(("CRITICAL", f"{h}: TCP endpoint with NO TLS client verification = unauthenticated root API"
                                    + (" reachable from every network interface" if public else " (loopback only, still reachable from local containers using host network)")))
        elif port == "2375":
            out.append(("MEDIUM", f"{h}: TLS configured but on the conventional plaintext port 2375: confusing, use 2376"))
    if "userns-remap" not in cfg and not cfg.get("rootless"):
        out.append(("MEDIUM", "no userns-remap: root in a container is root (UID 0) on the host"))
    if cfg.get("icc", True):
        out.append(("MEDIUM", "icc enabled on the default bridge: every container can talk to every other"))
    if not cfg.get("no-new-privileges"):
        out.append(("LOW", "no-new-privileges not set by default"))
    if not cfg.get("live-restore"):
        out.append(("LOW", "live-restore off: a daemon restart kills all containers"))
    if cfg.get("userland-proxy", True):
        out.append(("LOW", "userland-proxy on (default): extra attack surface and slower; consider disabling"))
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return sorted(out, key=lambda t: order.index(t[0]))


# ---------- 2. network segregation ----------
def flat_network_exposure(containers: list[dict]) -> list[str]:
    by_net: dict[str, list[str]] = {}
    for c in containers:
        for n in c["networks"]:
            by_net.setdefault(n, []).append(c["name"])
    out = []
    for net, members in by_net.items():
        if len(members) > 1 and net in ("bridge", "default"):
            pairs = len(members) * (len(members) - 1) // 2
            out.append(f"network '{net}' is flat: {len(members)} containers ({', '.join(members)}) = {pairs} reachable pairs; "
                       "one compromised container can scan and attack all the others")
    return out


# ---------- 3. denial of service ----------
def dos_exposure(containers: list[dict]) -> list[str]:
    out = []
    for c in containers:
        miss = [k for k in ("memory", "pids", "cpus") if not c.get(k)]
        if miss:
            out.append(f"{c['name']}: no {'/'.join(miss)} limit -> can exhaust the host's {', '.join(miss)}")
    return out


def fork_growth(pids_limit: int | None, host_pid_max: int = 32768, generations_max: int = 20) -> dict:
    """Arithmetic model of a fork bomb: every process makes one child per generation (population doubles).
    Nothing is forked here. Shows why `--pids-limit` is a cgroup control that protects the HOST."""
    pop, gen = 1, 0
    cap = pids_limit if pids_limit else host_pid_max
    while pop < cap and gen < generations_max:
        pop = min(pop * 2, cap)
        gen += 1
    return {"generations_to_cap": gen, "final_processes": pop, "hit": "container pids limit" if pids_limit else "HOST pid_max (host-wide outage)",
            "host_impact": "none: other containers unaffected" if pids_limit and pids_limit < host_pid_max // 4 else "severe: new processes fail everywhere"}


# ---------- 4. kernel exploits ----------
KERNEL_CVES = [   # FIXTURE data with made-up ids; real data: distro security trackers, NVD (verify at source)
    {"id": "FIXTURE-K-001", "introduced": "4.0", "fixed": "5.15.100", "type": "container escape via cgroup", "needs": "CAP_SYS_ADMIN or user namespaces"},
    {"id": "FIXTURE-K-002", "introduced": "5.8", "fixed": "5.16.11", "type": "local privilege escalation (pipe buffer flag)", "needs": "any local code, no extra privileges"},
    {"id": "FIXTURE-K-003", "introduced": "5.0", "fixed": "6.1.20", "type": "use-after-free in netfilter", "needs": "user namespaces or CAP_NET_ADMIN"},
    {"id": "FIXTURE-K-004", "introduced": "6.5", "fixed": "6.8.0", "type": "overlayfs permission bypass", "needs": "ability to mount overlayfs (user namespaces)"},
]


def _v(s: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", s.split("-")[0])[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


def kernel_risk(kernel: str, cves: list[dict] = KERNEL_CVES) -> list[dict]:
    """Which fixture flaws affect this host kernel? Every container on the host inherits them: no VM boundary."""
    k = _v(kernel)
    return [dict(c, kernel=kernel) for c in cves if _v(c["introduced"]) <= k < _v(c["fixed"])]
