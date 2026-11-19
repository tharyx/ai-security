"""A docker-bench-security-like auditor over a config bundle (no Docker needed).

The bundle JSON has: host, files (owner/mode), daemon (daemon.json), containers
(docker-inspect-shaped). Check ids are CIS Docker Benchmark-STYLE section numbers
(1 host, 2 daemon, 3 files, 4 images, 5 containers). Numbers and wording change
between benchmark versions: verify against the version you are audited on.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
SENSITIVE_MOUNTS = ("/", "/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr")


@dataclass
class CheckResult:
    id: str
    title: str
    severity: str  # high | medium | low
    passed: bool
    details: list[str] = field(default_factory=list)

    @property
    def section(self) -> str:
        return self.id.split(".")[0]


SECTION_NAMES = {"1": "Host configuration", "2": "Docker daemon configuration", "3": "Configuration files",
                 "4": "Container images and build", "5": "Container runtime"}


def _mode_ok(mode: str, max_mode: str) -> bool:
    """True when every permission bit in mode is allowed by max_mode (e.g. 0660 within 0660)."""
    return (int(mode, 8) & ~int(max_mode, 8)) == 0


def _file(b: dict, path: str) -> dict:
    return b.get("files", {}).get(path, {})


def _name(c: dict) -> str:
    return c.get("Name", "?").lstrip("/")


def _per_container(b, pred, msg):
    return [f"{_name(c)}: {msg}" for c in b.get("containers", []) if pred(c)]


def _binds(c):
    return c["HostConfig"].get("Binds") or []


def _sock_mounted(c):
    return any("docker.sock" in x for x in _binds(c))


def _sensitive(c):
    return [x for x in _binds(c) if x.split(":")[0] in SENSITIVE_MOUNTS]


def _tcp_without_tls(d):
    hosts = [h for h in d.get("hosts", []) if h.startswith("tcp://")]
    ok = d.get("tlsverify") and d.get("tlscacert") and d.get("tlscert") and d.get("tlskey")
    return hosts if hosts and not ok else []


# (id, title, severity, function(bundle) -> list of failure details)
CHECKS = [
    ("1.1.1", "Separate partition for /var/lib/docker (containers)", "low",
     lambda b: [] if b["host"].get("docker_partition_separate") else ["/var/lib/docker shares the root filesystem"]),
    ("1.1.3", "Audit rule for the Docker daemon (/usr/bin/dockerd)", "medium",
     lambda b: [] if "/usr/bin/dockerd" in b["host"].get("auditd_watches", []) else ["no auditd watch"]),
    ("1.1.5", "Audit rule for /var/lib/docker", "medium",
     lambda b: [] if "/var/lib/docker" in b["host"].get("auditd_watches", []) else ["no auditd watch"]),
    ("1.1.6", "Audit rule for /etc/docker", "medium",
     lambda b: [] if "/etc/docker" in b["host"].get("auditd_watches", []) else ["no auditd watch"]),
    ("1.2.2", "Only trusted users in the docker group", "high",
     lambda b: [f"unapproved user in docker group: {u}" for u in b["host"].get("docker_group_members", [])
                if u not in b["host"].get("approved_docker_users", [])]),
    ("2.2", "Restrict network traffic between containers on the default bridge (icc=false)", "medium",
     lambda b: [] if b["daemon"].get("icc") is False else ["icc not set to false"]),
    ("2.5", "No insecure registries", "high",
     lambda b: [f"insecure registry {r}" for r in b["daemon"].get("insecure-registries", [])]),
    ("2.6", "TLS authentication for the Docker daemon if it listens on TCP", "high",
     lambda b: [f"{h} without full tlsverify config" for h in _tcp_without_tls(b["daemon"])]),
    ("2.8", "User namespace support (userns-remap) enabled", "medium",
     lambda b: [] if b["daemon"].get("userns-remap") else ["userns-remap not set"]),
    ("2.12", "Centralized and remote logging configured", "low",
     lambda b: [] if b["daemon"].get("log-driver", "json-file") not in ("json-file", "local", "none")
     else ["log driver keeps logs only on the host"]),
    ("2.14", "Live restore enabled", "low",
     lambda b: [] if b["daemon"].get("live-restore") else ["live-restore off"]),
    ("2.15", "Userland proxy disabled", "low",
     lambda b: [] if b["daemon"].get("userland-proxy") is False else ["userland-proxy on"]),
    ("2.18", "Containers restricted from acquiring new privileges (daemon default)", "medium",
     lambda b: [] if b["daemon"].get("no-new-privileges") else ["no-new-privileges not default"]),
    ("3.1", "docker.service owned by root:root", "medium",
     lambda b: [] if _file(b, "/usr/lib/systemd/system/docker.service").get("owner") == "root:root" else ["wrong owner"]),
    ("3.2", "docker.service permissions 644 or stricter", "medium",
     lambda b: [] if _mode_ok(_file(b, "/usr/lib/systemd/system/docker.service").get("mode", "0777"), "0644") else ["too open"]),
    ("3.15", "docker.sock owned by root:docker", "high",
     lambda b: [] if _file(b, "/var/run/docker.sock").get("owner") == "root:docker" else ["wrong owner"]),
    ("3.16", "docker.sock permissions 660 or stricter", "high",
     lambda b: [] if _mode_ok(_file(b, "/var/run/docker.sock").get("mode", "0777"), "0660") else
     [f"mode {_file(b, '/var/run/docker.sock').get('mode')} lets others use the daemon"]),
    ("3.17", "daemon.json owned by root:root", "medium",
     lambda b: [] if _file(b, "/etc/docker/daemon.json").get("owner") == "root:root" else ["wrong owner"]),
    ("3.18", "daemon.json permissions 644 or stricter", "medium",
     lambda b: [] if _mode_ok(_file(b, "/etc/docker/daemon.json").get("mode", "0777"), "0644") else ["too open"]),
    ("4.1", "Containers run as a non-root user", "high",
     lambda b: _per_container(b, lambda c: c["Config"].get("User", "") in ("", "root", "0"), "runs as root")),
    ("4.6", "HEALTHCHECK present", "low",
     lambda b: _per_container(b, lambda c: not c["Config"].get("Healthcheck"), "no healthcheck")),
    ("5.2", "AppArmor or SELinux profile applied", "medium",
     lambda b: _per_container(b, lambda c: not any(s.startswith(("apparmor", "label=")) for s in c["HostConfig"].get("SecurityOpt") or []), "no LSM profile")),
    ("5.3", "No dangerous added Linux capabilities", "high",
     lambda b: _per_container(b, lambda c: bool(DANGEROUS_CAPS & {x.upper().removeprefix("CAP_") for x in c["HostConfig"].get("CapAdd") or []}), "dangerous CapAdd")),
    ("5.4", "No privileged containers", "high",
     lambda b: _per_container(b, lambda c: c["HostConfig"].get("Privileged"), "privileged")),
    ("5.5", "Sensitive host directories not mounted", "high",
     lambda b: [f"{_name(c)}: mounts {m}" for c in b["containers"] for m in _sensitive(c)]),
    ("5.9", "Host network namespace not shared", "high",
     lambda b: _per_container(b, lambda c: c["HostConfig"].get("NetworkMode") == "host", "network=host")),
    ("5.10", "Memory limit set", "medium",
     lambda b: _per_container(b, lambda c: not c["HostConfig"].get("Memory"), "no memory limit")),
    ("5.11", "CPU priority/limit set", "low",
     lambda b: _per_container(b, lambda c: not (c["HostConfig"].get("CpuShares") or c["HostConfig"].get("NanoCpus")), "no CPU limit")),
    ("5.12", "Root filesystem mounted read-only", "medium",
     lambda b: _per_container(b, lambda c: not c["HostConfig"].get("ReadonlyRootfs"), "writable rootfs")),
    ("5.14", "Restart policy on-failure limited (not always)", "low",
     lambda b: _per_container(b, lambda c: c["HostConfig"].get("RestartPolicy", {}).get("Name") == "always", "restart always")),
    ("5.15", "Host PID namespace not shared", "high",
     lambda b: _per_container(b, lambda c: c["HostConfig"].get("PidMode") == "host", "pid=host")),
    ("5.17", "Host devices not directly exposed", "medium",
     lambda b: _per_container(b, lambda c: bool(c["HostConfig"].get("Devices")), "host devices exposed")),
    ("5.25", "no-new-privileges set", "medium",
     lambda b: _per_container(b, lambda c: "no-new-privileges" not in " ".join(c["HostConfig"].get("SecurityOpt") or []), "can gain privileges")),
    ("5.28", "PIDs cgroup limit set", "medium",
     lambda b: _per_container(b, lambda c: not c["HostConfig"].get("PidsLimit"), "no pids limit (fork bomb)")),
    ("5.31", "docker.sock not mounted into containers", "high",
     lambda b: _per_container(b, _sock_mounted, "mounts docker.sock")),
]


def audit(bundle: dict) -> list[CheckResult]:
    out = []
    for cid, title, sev, fn in CHECKS:
        fails = fn(bundle)
        out.append(CheckResult(cid, title, sev, not fails, fails))
    return out


def score(results: list[CheckResult]) -> float:
    """Percent of checks passed (the simple docker-bench style score)."""
    return round(100 * sum(r.passed for r in results) / len(results), 1) if results else 0.0


def weighted_score(results: list[CheckResult]) -> float:
    w = {"high": 3, "medium": 2, "low": 1}
    tot = sum(w[r.severity] for r in results)
    return round(100 * sum(w[r.severity] for r in results if r.passed) / tot, 1) if tot else 0.0


def by_section(results: list[CheckResult]) -> dict[str, tuple[int, int]]:
    sec: dict[str, list[int]] = {}
    for r in results:
        p, t = sec.setdefault(r.section, [0, 0])
        sec[r.section] = [p + r.passed, t + 1]
    return {k: (v[0], v[1]) for k, v in sorted(sec.items())}


def exit_code(results: list[CheckResult], fail_on: str = "high") -> int:
    """1 if any failed check is at or above fail_on severity (use as a pipeline gate)."""
    order = {"low": 0, "medium": 1, "high": 2}
    return int(any((not r.passed) and order[r.severity] >= order[fail_on] for r in results))


def report(results: list[CheckResult], only_failures: bool = False) -> str:
    lines = []
    for r in results:
        if only_failures and r.passed:
            continue
        lines.append(f"[{'PASS' if r.passed else 'FAIL'}] {r.id:<5} ({r.severity:<6}) {r.title}")
        lines += [f"        - {d}" for d in r.details]
    return "\n".join(lines)
