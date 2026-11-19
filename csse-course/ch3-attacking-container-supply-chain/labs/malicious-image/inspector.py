"""Inspect an image config (and optional layer file listing) for signs of a malicious image.

Reads JSON only: the OCI image config you get from `docker image inspect` or from the registry blob.
Never runs anything from the image. Real tools: Trivy (misconfig and secrets), Dive, Syft + Grype, YARA rules.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
PIPE_TO_SHELL = re.compile(r"(curl|wget)\b[^|;]*\|\s*(ba|z|da)?sh\b")
DOWNLOAD_EXEC = re.compile(r"(curl|wget)\b.*(-O|-o|>)\s*\S+.*chmod\s+\+x", re.I)
ENCODED_EXEC = re.compile(r"base64\s+(-d|--decode)|/dev/tcp/|nc\s+-e|bash\s+-i", re.I)
MINER_WORDS = re.compile(r"(xmrig|minerd|stratum\+tcp|cryptonight|monero|coinhive|\bpool\.[a-z0-9.-]+)", re.I)
SECRET_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|API_?KEY|ACCESS_KEY)", re.I)
HIDDEN_BINARY = re.compile(r"^/(usr/(s?bin|local/bin)|bin|sbin|tmp|var/tmp)/\.[^/]+$")
BACKDOOR_PORTS = {"4444", "1337", "31337", "6666", "9001"}
CRON_PATHS = ("/etc/cron", "/var/spool/cron", "/etc/crontab")
TRUSTED_HOSTS = (".trusted.example",)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    where: str
    message: str


def _urls(text: str) -> list[str]:
    return re.findall(r"https?://([A-Za-z0-9.-]+)", text)


def inspect_config(cfg: dict) -> list[Finding]:
    out: list[Finding] = []
    c = cfg.get("config", {})
    launch = " ".join((c.get("Entrypoint") or []) + (c.get("Cmd") or []))
    if PIPE_TO_SHELL.search(launch):
        out.append(Finding("IMG-001", "CRITICAL", "Entrypoint/Cmd", "downloads a script and pipes it to a shell every time the container starts"))
    if ENCODED_EXEC.search(launch):
        out.append(Finding("IMG-002", "CRITICAL", "Entrypoint/Cmd", "encoded command or reverse-shell pattern at start"))
    for host in _urls(launch):
        if not host.endswith(TRUSTED_HOSTS):
            out.append(Finding("IMG-003", "HIGH", "Entrypoint/Cmd", f"start-up contacts unknown host {host}"))
    if c.get("User", "") in ("", "0", "root"):
        out.append(Finding("IMG-004", "MEDIUM", "Config.User", "image runs as root"))
    for env in c.get("Env", []):
        name, _, value = env.partition("=")
        if SECRET_ENV.search(name) and value:
            out.append(Finding("IMG-005", "HIGH", "Config.Env", f"secret-looking variable {name} baked into the image"))
    for port in (c.get("ExposedPorts") or {}):
        if port.split("/")[0] in BACKDOOR_PORTS:
            out.append(Finding("IMG-006", "HIGH", "Config.ExposedPorts", f"unusual port {port} (typical backdoor or C2 port)"))
    for i, h in enumerate(cfg.get("history", [])):
        cmd = h.get("created_by", "")
        if PIPE_TO_SHELL.search(cmd):
            out.append(Finding("IMG-007", "HIGH", f"history[{i}]", "build step pipes a download to a shell"))
        if DOWNLOAD_EXEC.search(cmd):
            out.append(Finding("IMG-008", "HIGH", f"history[{i}]", "build step downloads a binary and marks it executable"))
        if MINER_WORDS.search(cmd):
            out.append(Finding("IMG-009", "HIGH", f"history[{i}]", "build step mentions mining software"))
        if re.search(r"/etc/cron|crontab", cmd):
            out.append(Finding("IMG-010", "MEDIUM", f"history[{i}]", "build step installs a cron job"))
    return sorted(out, key=lambda f: -SEVERITY[f.severity])


def inspect_files(files: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    for path, content in files.items():
        if path.startswith(CRON_PATHS):
            out.append(Finding("FS-001", "MEDIUM", path, "scheduled job inside the image; why does this service need cron?"))
        if HIDDEN_BINARY.match(path):
            out.append(Finding("FS-002", "HIGH", path, "hidden dot-file in a binary directory"))
        if MINER_WORDS.search(content):
            out.append(Finding("FS-003", "CRITICAL", path, "mining pool or miner string (simulated) in file content"))
        if path.endswith("authorized_keys"):
            out.append(Finding("FS-004", "HIGH", path, "baked-in SSH key lets someone log in"))
    return sorted(out, key=lambda f: -SEVERITY[f.severity])


def verdict(findings: list[Finding]) -> str:
    worst = max((SEVERITY[f.severity] for f in findings), default=0)
    return "BLOCK" if worst >= 3 else "REVIEW" if worst >= 2 else "ALLOW"


def inspect_files_path(config_path: Path, layers_path: Path | None = None) -> list[Finding]:
    found = inspect_config(json.loads(Path(config_path).read_text()))
    if layers_path:
        found += inspect_files(json.loads(Path(layers_path).read_text())["files"])
    return sorted(found, key=lambda f: -SEVERITY[f.severity])
