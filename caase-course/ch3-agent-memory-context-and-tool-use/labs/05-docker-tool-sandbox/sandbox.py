"""Sandboxing tool execution: a docker-run policy generator plus a subprocess sandbox twin.

Part 1, ``SandboxPolicy`` -> ``build_docker_args``: builds a hardened ``docker run`` command line
(no network, read-only root filesystem, non-root user, all capabilities dropped, no-new-privileges,
memory/CPU/PID limits, a small noexec tmpfs, read-only mounts). ``validate_policy`` refuses unsafe
policies, and the builder fails closed. The tests check the generated arguments; **Docker is not needed
and is never started**.

Part 2, ``SubprocessSandbox``: a portable twin that shows the *policy ideas* with a plain subprocess:
scrubbed environment (no secrets), private working directory, timeout, output cap. It is NOT kernel
isolation: it cannot stop network or file access. That is why the real boundary is the container,
a microVM or a gVisor-style runtime.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.I)
SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/var/run/docker.sock", "/run/docker.sock", "C:\\", "C:/")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class SandboxPolicy:
    image: str = "agent-tool-sandbox:1.0"
    command: tuple[str, ...] = ("python", "/app/tool.py")
    network: str = "none"
    read_only: bool = True
    user: str = "10001:10001"
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    memory: str = "256m"
    cpus: str = "0.5"
    pids_limit: int = 64
    tmpfs: tuple[str, ...] = ("/tmp:rw,noexec,nosuid,size=16m",)
    mounts: tuple[tuple[str, str, str], ...] = ()   # (host path, container path, "ro"|"rw")
    env: tuple[tuple[str, str], ...] = ()
    privileged: bool = False


def validate_policy(p: SandboxPolicy, allowed_host_roots: tuple[str, ...] = ()) -> list[str]:
    problems = []
    if p.privileged:
        problems.append("privileged containers are forbidden")
    if p.network != "none":
        problems.append("network must be 'none'")
    if not p.read_only:
        problems.append("root filesystem must be read-only")
    if p.user.split(":")[0] in ("", "0", "root"):
        problems.append("must run as a non-root user")
    if "ALL" not in p.cap_drop:
        problems.append("must drop ALL capabilities")
    if not p.no_new_privileges:
        problems.append("no-new-privileges must be set")
    if not (p.memory and p.cpus and p.pids_limit > 0):
        problems.append("memory, cpu and pids limits are required")
    if p.image.endswith(":latest") or (":" not in p.image.split("/")[-1] and "@" not in p.image):
        problems.append("image must be pinned (tag or digest, not latest)")
    for host, _ctr, mode in p.mounts:
        if host.rstrip("/\\") in SENSITIVE_HOST_PATHS or "docker.sock" in host:
            problems.append(f"mount of sensitive host path {host}")
        if mode != "ro":
            problems.append(f"mount {host} must be read-only")
        if allowed_host_roots and not host.startswith(allowed_host_roots):
            problems.append(f"mount {host} outside allowed roots")
    for k, _v in p.env:
        if SECRET_NAME.search(k):
            problems.append(f"secret-looking environment variable {k}")
    return problems


def build_docker_args(p: SandboxPolicy, allowed_host_roots: tuple[str, ...] = ()) -> list[str]:
    problems = validate_policy(p, allowed_host_roots)
    if problems:
        raise PolicyError("; ".join(problems))  # fail closed: no command line for an unsafe policy
    args = ["docker", "run", "--rm", "--network", p.network, "--read-only", "--user", p.user]
    for c in p.cap_drop:
        args += ["--cap-drop", c]
    args += ["--security-opt", "no-new-privileges"]
    args += ["--memory", p.memory, "--cpus", p.cpus, "--pids-limit", str(p.pids_limit)]
    for t in p.tmpfs:
        args += ["--tmpfs", t]
    for host, ctr, mode in p.mounts:
        args += ["-v", f"{host}:{ctr}:{mode}"]
    for k, v in p.env:
        args += ["-e", f"{k}={v}"]
    return args + [p.image, *p.command]


# ---- portable twin -----------------------------------------------------------------
@dataclass
class SandboxResult:
    returncode: int | None
    stdout: str
    timed_out: bool = False
    truncated: bool = False


@dataclass
class SubprocessSandbox:
    timeout_s: float = 2.0
    max_output: int = 2000
    keep_env: tuple[str, ...] = ("SYSTEMROOT",)  # Windows needs this to start Python; Linux needs nothing
    scrub_env: bool = True
    log: list[str] = field(default_factory=list)

    def run_python(self, code: str) -> SandboxResult:
        env = ({k: os.environ[k] for k in self.keep_env if k in os.environ}
               if self.scrub_env else dict(os.environ))
        with tempfile.TemporaryDirectory() as work:  # private working directory, deleted afterwards
            try:
                cp = subprocess.run([sys.executable, "-I", "-c", code], cwd=work, env=env, capture_output=True,
                                    text=True, timeout=self.timeout_s)
            except subprocess.TimeoutExpired:
                self.log.append("timeout-killed")
                return SandboxResult(None, "", timed_out=True)
        out = cp.stdout
        truncated = len(out) > self.max_output
        if truncated:
            self.log.append("output-truncated")
        return SandboxResult(cp.returncode, out[: self.max_output], truncated=truncated)
