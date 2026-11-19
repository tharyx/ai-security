"""Container escape-path ANALYZER. Purely analytical: it reads a container configuration and says which
settings open a way from the container to the host, why, and how to close it. It contains NO exploit code
and executes nothing.

Input is a simplified `docker inspect` document plus an optional list of SetUID files found in the image.
"""
from __future__ import annotations

from dataclasses import dataclass

CAP_EXPLAIN = {
    "SYS_ADMIN": ("CRITICAL", "CAP_SYS_ADMIN is 'the new root': it allows mounting file systems, using many namespace and cgroup "
                  "operations and more. Combined with a weak seccomp/AppArmor profile it is the classic breakout enabler."),
    "SYS_PTRACE": ("HIGH", "CAP_SYS_PTRACE lets a process inspect and alter other processes. If the PID namespace is shared with the "
                   "host, that includes host processes and their memory (secrets)."),
    "DAC_READ_SEARCH": ("HIGH", "CAP_DAC_READ_SEARCH bypasses file read permission checks and allows opening files by handle. "
                        "Historically abused to read arbitrary host files when paired with host-visible mounts."),
    "SYS_MODULE": ("CRITICAL", "CAP_SYS_MODULE allows loading kernel modules: code running in the host kernel."),
    "NET_ADMIN": ("MEDIUM", "CAP_NET_ADMIN lets the container change network configuration (routes, firewall); dangerous with host networking."),
    "DAC_OVERRIDE": ("MEDIUM", "CAP_DAC_OVERRIDE bypasses file write/execute permission checks inside every mounted path."),
}
HOST_SENSITIVE = {"/": "the entire host file system", "/etc": "host config, shadow and sudoers", "/root": "root's home and SSH keys",
                  "/var/lib/docker": "every container's layers and volumes", "/proc": "kernel and process interfaces",
                  "/sys": "kernel and device interfaces", "/boot": "kernel and boot loader", "/home": "user data"}
SOCKETS = ("/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd/containerd.sock", "/run/containerd/containerd.sock")


@dataclass(frozen=True)
class EscapePath:
    id: str
    severity: str
    title: str
    why: str
    fix: str


def _binds(cfg: dict) -> list[tuple[str, str, bool]]:
    out = []
    for b in cfg.get("HostConfig", {}).get("Binds") or []:
        parts = b.split(":")
        out.append((parts[0], parts[1] if len(parts) > 1 else "", "ro" in (parts[2].split(",") if len(parts) > 2 else [])))
    return out


def analyze(cfg: dict, setuid_files: list[str] | None = None) -> list[EscapePath]:
    hc = cfg.get("HostConfig", {})
    caps = {c.upper().removeprefix("CAP_") for c in hc.get("CapAdd") or []}
    secopt = hc.get("SecurityOpt") or []
    user = cfg.get("Config", {}).get("User") or "root"
    out: list[EscapePath] = []

    if hc.get("Privileged"):
        out.append(EscapePath("ESC-PRIV", "CRITICAL", "Privileged mode",
                              "--privileged grants every capability, access to host devices and switches off the default seccomp and AppArmor "
                              "confinement. The container boundary is mostly gone: with device access root in the container can mount the host disk.",
                              "Remove --privileged; add only the single capability or --device that is needed."))
    for src, dst, ro in _binds(cfg):
        if any(src == s for s in SOCKETS):
            out.append(EscapePath("ESC-SOCK", "CRITICAL", f"Container runtime socket mounted ({src})",
                                  "The socket is the daemon's API. A process that can write to it can ask the daemon (which runs as root) to start a new "
                                  "container with any mount and privilege. Mounting it equals root on the host, even with :ro (read-only does not stop API calls).",
                                  "Do not mount it. Use a socket proxy with an allow-list, a rootless daemon, or build tools that need no daemon (BuildKit, kaniko)."))
        elif src == "/" or src in HOST_SENSITIVE:
            sev = "CRITICAL" if (src == "/" and not ro) else "HIGH"
            out.append(EscapePath("ESC-HOSTMOUNT", sev, f"Sensitive host path mounted ({src}{' read-only' if ro else ''})",
                                  f"Mounting {src} exposes {HOST_SENSITIVE[src]}." + (" Read-write means the container can change it." if not ro else " Read-only still leaks secrets."),
                                  "Mount only the specific sub-directory needed, read-only, or use a named volume."))
    if hc.get("PidMode") == "host":
        out.append(EscapePath("ESC-HOSTPID", "HIGH", "Shared host PID namespace",
                              "The container sees every host process, their command lines and (with ptrace or root) their /proc entries, environment variables and memory.",
                              "Remove --pid host; use --pid container:<id> only for short debug sessions."))
    if hc.get("NetworkMode") == "host":
        out.append(EscapePath("ESC-HOSTNET", "HIGH", "Shared host network namespace",
                              "The container shares the host network stack: it reaches services bound to localhost (databases, the metadata service, a 127.0.0.1 Docker API) and can sniff host traffic with NET_RAW.",
                              "Use a bridge network and publish only the ports needed."))
    if hc.get("IpcMode") == "host":
        out.append(EscapePath("ESC-HOSTIPC", "MEDIUM", "Shared host IPC namespace",
                              "Shared-memory segments and message queues of host processes become readable or writable from the container.",
                              "Leave IPC private."))
    for cap in sorted(caps & set(CAP_EXPLAIN)):
        sev, why = CAP_EXPLAIN[cap]
        out.append(EscapePath(f"ESC-CAP-{cap}", sev, f"Dangerous capability {cap}", why, f"--cap-drop ALL, then add back only what the app needs (not {cap})."))
    if setuid_files:
        sev = "HIGH" if "no-new-privileges" not in " ".join(secopt) and user not in ("root", "0") else "LOW"
        out.append(EscapePath("ESC-SETUID", sev, f"SetUID/SetGID binaries in the image ({', '.join(setuid_files)})",
                              "A SetUID binary runs with its owner's rights (often root). If it has a flaw or a risky feature, a low-privileged process in the container "
                              "can become root inside it, which is then the starting point for any other path above.",
                              "Run with --security-opt no-new-privileges, strip the bits (chmod u-s,g-s) in the Dockerfile, use a minimal or distroless base."))
    if any(o in ("seccomp=unconfined", "apparmor=unconfined") for o in secopt) and not hc.get("Privileged"):
        out.append(EscapePath("ESC-LSM-OFF", "HIGH", "Seccomp or AppArmor disabled",
                              "The kernel attack surface exposed to the container grows to every system call. Many kernel breakouts rely on calls the default profile blocks.",
                              "Keep the default profile or write a custom one."))
    if user in ("root", "0") and not out:
        out.append(EscapePath("ESC-ROOT", "LOW", "Runs as root inside the container",
                              "No direct escape path found, but container root plus any future kernel flaw is worse than an unprivileged user.",
                              "USER with a numeric non-root UID; consider user namespaces or rootless mode."))
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return sorted(out, key=lambda p: (order.index(p.severity), p.id))


def verdict(paths: list[EscapePath]) -> str:
    if any(p.severity == "CRITICAL" for p in paths):
        return "DENY"
    if any(p.severity == "HIGH" for p in paths):
        return "REVIEW"
    return "OK" if not paths else "WARN"
