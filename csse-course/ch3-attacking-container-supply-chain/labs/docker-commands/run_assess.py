"""Parse `docker run` flags into a security assessment (no Docker needed).

    python run_assess.py "docker run --privileged -v /var/run/docker.sock:/var/run/docker.sock nginx:latest"

It reads the command as text only. Nothing is executed. The point: most container
breakouts begin with a run flag someone added "just to make it work".
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "NET_RAW", "DAC_READ_SEARCH", "SYS_RAWIO"}
SENSITIVE_HOST_PATHS = {"/", "/etc", "/root", "/proc", "/sys", "/var/run/docker.sock", "/run/docker.sock", "/var/lib/docker", "/dev"}
SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY)", re.I)
VALUE_FLAGS = {"-v", "--volume", "--mount", "--cap-add", "--cap-drop", "--network", "--net", "--pid", "--ipc", "--user", "-u",
               "--security-opt", "--device", "-p", "--publish", "-e", "--env", "--name", "--memory", "-m", "--cpus",
               "--pids-limit", "--restart", "--hostname", "-h", "-w", "--workdir", "--entrypoint", "--tmpfs", "--userns", "--uts"}


@dataclass
class RunConfig:
    image: str = ""
    privileged: bool = False
    volumes: list[str] = field(default_factory=list)
    cap_add: list[str] = field(default_factory=list)
    cap_drop: list[str] = field(default_factory=list)
    network: str = "bridge"
    pid: str = ""
    ipc: str = ""
    user: str = ""
    read_only: bool = False
    security_opt: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    memory: str = ""
    pids_limit: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str


def parse_run(command: str) -> RunConfig:
    tokens = shlex.split(command)
    if tokens[:2] != ["docker", "run"]:
        raise ValueError("expected a 'docker run ...' command")
    cfg, i = RunConfig(), 2
    while i < len(tokens):
        tok = tokens[i]
        if not tok.startswith("-"):
            cfg.image = tok  # first positional argument is the image; the rest is the container command
            break
        flag, eq, inline = tok.partition("=")
        if flag in VALUE_FLAGS and not eq:
            i += 1
            inline = tokens[i] if i < len(tokens) else ""
        elif flag not in VALUE_FLAGS and not eq:
            inline = ""
        if flag == "--privileged":
            cfg.privileged = inline.lower() != "false"
        elif flag in ("-v", "--volume"):
            cfg.volumes.append(inline)
        elif flag == "--mount":
            parts = dict(p.split("=", 1) for p in inline.split(",") if "=" in p)
            cfg.volumes.append(f"{parts.get('source') or parts.get('src', '')}:{parts.get('target') or parts.get('dst', '')}")
        elif flag == "--cap-add":
            cfg.cap_add.append(inline.upper().removeprefix("CAP_"))
        elif flag == "--cap-drop":
            cfg.cap_drop.append(inline.upper().removeprefix("CAP_"))
        elif flag in ("--network", "--net"):
            cfg.network = inline
        elif flag == "--pid":
            cfg.pid = inline
        elif flag == "--ipc":
            cfg.ipc = inline
        elif flag in ("--user", "-u"):
            cfg.user = inline
        elif flag == "--read-only":
            cfg.read_only = True
        elif flag == "--security-opt":
            cfg.security_opt.append(inline)
        elif flag == "--device":
            cfg.devices.append(inline)
        elif flag in ("-p", "--publish"):
            cfg.ports.append(inline)
        elif flag in ("-e", "--env"):
            cfg.env.append(inline)
        elif flag in ("-m", "--memory"):
            cfg.memory = inline
        elif flag == "--pids-limit":
            cfg.pids_limit = inline
        i += 1
    if not cfg.image:
        raise ValueError("no image found")
    return cfg


def assess(cfg: RunConfig) -> list[Finding]:
    out: list[Finding] = []

    def add(rule_id: str, sev: str, msg: str) -> None:
        out.append(Finding(rule_id, sev, msg))

    if cfg.privileged:
        add("RUN-001", "CRITICAL", "--privileged: all capabilities, all devices, no seccomp/AppArmor confinement")
    for vol in cfg.volumes:
        parts = vol.split(":")
        src = parts[0]
        read_only = len(parts) > 2 and "ro" in parts[2].split(",")
        if src.endswith("docker.sock"):
            add("RUN-002", "CRITICAL", f"mounts {src}: whoever controls it controls the host (can start a privileged container)")
        elif src in SENSITIVE_HOST_PATHS or (src != "/" and src.rstrip("/") in SENSITIVE_HOST_PATHS):
            add("RUN-003", "HIGH", f"bind-mounts sensitive host path {src}")
        elif src.startswith("/") and not read_only:
            add("RUN-004", "MEDIUM", f"host path {src} is mounted writable; prefer :ro or a named volume")
    bad = sorted(DANGEROUS_CAPS & set(cfg.cap_add))
    if bad:
        add("RUN-005", "HIGH", f"--cap-add {bad}: broad kernel powers (SYS_ADMIN is nearly root)")
    if "ALL" not in cfg.cap_drop and not cfg.privileged:
        add("RUN-006", "MEDIUM", "capabilities not dropped: use --cap-drop ALL and add back only what is needed")
    if cfg.network == "host":
        add("RUN-007", "HIGH", "--network host: shares the host network stack (reaches localhost services)")
    if cfg.pid == "host":
        add("RUN-008", "HIGH", "--pid host: sees and can signal host processes")
    if cfg.ipc == "host":
        add("RUN-009", "MEDIUM", "--ipc host: shares host IPC")
    if cfg.user in ("", "0", "root") or cfg.user.startswith(("0:", "root:")):
        add("RUN-010", "MEDIUM", "runs as root (set --user 10001:10001)")
    if not cfg.read_only:
        add("RUN-011", "LOW", "root filesystem is writable (use --read-only plus --tmpfs /tmp)")
    for opt in cfg.security_opt:
        if opt in ("seccomp=unconfined", "apparmor=unconfined", "label=disable", "systempaths=unconfined"):
            add("RUN-012", "HIGH", f"--security-opt {opt} turns a confinement layer off")
    if not any(o.startswith("no-new-privileges") for o in cfg.security_opt):
        add("RUN-013", "LOW", "no-new-privileges not set (setuid binaries can still raise privileges)")
    for dev in cfg.devices:
        add("RUN-014", "HIGH", f"--device {dev.split(':')[0]}: direct hardware or kernel device access")
    for env in cfg.env:
        name, _, value = env.partition("=")
        if SECRET_NAME.search(name) and value:
            add("RUN-015", "HIGH", f"secret '{name}' passed on the command line (visible in docker inspect and shell history)")
    for port in cfg.ports:
        if not port.startswith("127.0.0.1:") and ":" in port:
            add("RUN-016", "MEDIUM", f"port {port} is published on all interfaces; bind to 127.0.0.1 if it is local only")
    ref = cfg.image
    if "@sha256:" not in ref and (":" not in ref.rsplit("/", 1)[-1] or ref.endswith(":latest")):
        add("RUN-017", "MEDIUM", f"image '{ref}' is untagged or 'latest'; pin by digest")
    if not cfg.memory or not cfg.pids_limit:
        add("RUN-018", "LOW", "no --memory / --pids-limit: one container can starve the host (fork bomb, memory)")
    return sorted(out, key=lambda f: -SEVERITY[f.severity])


def risk_score(findings: list[Finding]) -> int:
    weights = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15}
    return min(100, sum(weights[f.severity] for f in findings))


def verdict(findings: list[Finding]) -> str:
    worst = max((SEVERITY[f.severity] for f in findings), default=0)
    return "DENY" if worst >= 4 else "REVIEW" if worst >= 3 else "WARN" if worst >= 2 else "OK"


if __name__ == "__main__":
    import sys

    fs = assess(parse_run(sys.argv[1]))
    for f in fs:
        print(f"[{f.severity:8}] {f.rule_id} {f.message}")
    print(f"verdict={verdict(fs)} score={risk_score(fs)}")
