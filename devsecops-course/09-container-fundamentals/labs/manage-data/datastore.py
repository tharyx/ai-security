"""Docker data options: volumes vs bind mounts vs tmpfs, with a persistence simulation and a risk analysis.

Writable container layer: lost when the container is removed.
Volume (-v name:/path): managed by Docker under /var/lib/docker/volumes; survives `rm`.
Bind mount (-v /host/path:/path): a host path; survives `rm`; the container can touch the HOST file system.
tmpfs (--tmpfs /path): RAM only; gone when the container stops.
"""
from __future__ import annotations

from dataclasses import dataclass

SENSITIVE_HOST_PATHS = {
    "/": "the whole host file system",
    "/etc": "host configuration, passwd, shadow, sudoers",
    "/root": "root's home (ssh keys, shell history)",
    "/var/run/docker.sock": "the Docker API (equals root on the host)",
    "/run/docker.sock": "the Docker API (equals root on the host)",
    "/var/lib/docker": "all images, layers and volumes of every container",
    "/proc": "kernel and process interfaces",
    "/sys": "kernel and device interfaces",
    "/home": "user home directories",
}


@dataclass
class Mount:
    kind: str          # volume | bind | tmpfs | anonymous
    source: str        # volume name or host path ('' for tmpfs/anonymous)
    target: str
    read_only: bool = False


def parse_v(spec: str) -> Mount:
    """Parse the short -v syntax: 'src:dst[:ro]' or just 'dst' (anonymous volume)."""
    parts = spec.split(":")
    if len(parts) == 1:
        return Mount("anonymous", "", parts[0])
    ro = len(parts) > 2 and "ro" in parts[2].split(",")
    kind = "bind" if parts[0].startswith(("/", ".", "~")) else "volume"
    return Mount(kind, parts[0], parts[1], ro)


def risks(m: Mount) -> list[tuple[str, str]]:
    out = []
    if m.kind == "bind":
        for path, what in SENSITIVE_HOST_PATHS.items():
            src = m.source.rstrip("/") or "/"
            if src == path or (path != "/" and src.startswith(path + "/")):
                sev = "CRITICAL" if not m.read_only or path.endswith("docker.sock") else "HIGH"
                out.append((sev, f"bind mount of {m.source} exposes {what}" + ("" if m.read_only else " read-write")))
                break
        else:
            if not m.read_only:
                out.append(("MEDIUM", f"bind mount {m.source} is read-write: a compromised container can modify host files (use :ro)"))
    if m.kind == "anonymous":
        out.append(("LOW", f"anonymous volume at {m.target}: easy to lose track of, hard to back up and clean up"))
    if m.kind == "volume" and not m.read_only and m.target in ("/etc", "/usr", "/bin"):
        out.append(("MEDIUM", f"volume over system path {m.target} can hide image content"))
    return out


class Host:
    """A fake host that shows what survives `docker rm`."""

    def __init__(self):
        self.volumes: dict[str, dict[str, str]] = {}
        self.host_fs: dict[str, str] = {"/srv/app-config/app.conf": "setting=1"}

    def run(self, mounts: list[Mount]) -> "Container":
        for m in mounts:
            if m.kind in ("volume", "anonymous"):
                self.volumes.setdefault(m.source or f"anon-{len(self.volumes)}", {})
        return Container(self, mounts)


class Container:
    def __init__(self, host: Host, mounts: list[Mount]):
        self.host, self.mounts = host, mounts
        self.layer: dict[str, str] = {}
        self.tmpfs: dict[str, str] = {}
        self.running = True

    def _mount_for(self, path: str) -> Mount | None:
        best = None
        for m in self.mounts:
            if path == m.target or path.startswith(m.target.rstrip("/") + "/"):
                if best is None or len(m.target) > len(best.target):
                    best = m
        return best

    def write(self, path: str, data: str) -> str:
        m = self._mount_for(path)
        if m is None:
            self.layer[path] = data
            return "writable layer"
        if m.read_only:
            raise PermissionError(f"{m.target} is mounted read-only")
        if m.kind == "tmpfs":
            self.tmpfs[path] = data
            return "tmpfs (RAM)"
        if m.kind == "bind":
            self.host.host_fs[m.source.rstrip("/") + path[len(m.target.rstrip("/")):]] = data
            return f"HOST path {m.source}"
        self.host.volumes[m.source or next(reversed(self.host.volumes))][path] = data
        return f"volume {m.source or '(anonymous)'}"

    def stop(self):
        self.running = False
        self.tmpfs.clear()

    def rm(self):
        self.stop()
        self.layer.clear()
