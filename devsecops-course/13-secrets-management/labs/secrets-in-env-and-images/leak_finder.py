"""Find secrets leaked through environment variables, image config, `docker inspect`, image history,
compose files, logs and /proc/<pid>/environ. Then fix with runtime injection. Offline; reads JSON/YAML/text only.

Where the same secret leaks (all of them are separate doors):
  image config Env / history   anyone who can PULL the image (registry readers, CI caches, mirrors)
  docker inspect               anyone in the docker group or with API access (= root on the host)
  /proc/<pid>/environ          the same user or root on the host (and some sidecars/debug tools)
  logs and crash dumps         everyone with log access: wide, long-lived, copied to SIEM
  compose / .env files         git history, laptops, backups

Fix: do not put the secret in the image or in the environment. Inject at runtime as a file on tmpfs
(Docker/Swarm secrets, Kubernetes Secret volume via External Secrets or CSI) or fetch from a secrets manager
with a short-lived identity; the app reads NAME_FILE. Rotate anything that ever leaked.

Real-tool twins: Trivy (secret scanner), TruffleHog, gitleaks, Dockle, `docker history --no-trunc`, `docker inspect`.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|DSN)", re.I)
URL_CREDS = re.compile(r"[a-z][a-z0-9+.-]*://([^/\s:@]+):([^/\s@]+)@", re.I)
BEARER = re.compile(r"Bearer\s+([A-Za-z0-9._~+/=-]{8,})")
KV_IN_TEXT = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{2,})=([^\s'\"]+)")
SECRET_FILE = re.compile(r"(^|/)(\.env|id_rsa|id_ed25519|credentials|\.npmrc|\.netrc|[^/]*\.pem|[^/]*\.key|[^/]*\.pfx)$")
BUILD_ARG_PREFIX = re.compile(r"^\|\d+ (.*?) /bin/sh -c ")
SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class Finding:
    source: str      # where the leak was found
    location: str    # which field or line
    kind: str
    name: str
    severity: str
    evidence: str    # always redacted


def redact(value: str) -> str:
    return (value[:2] + "***") if len(value) > 4 else "***"


def is_reference(value: str) -> bool:
    return value == "" or value.startswith(("/run/secrets/", "${", "vault:", "ref+")) or "{{" in value


def secret_like(name: str, value: str) -> bool:
    if name.upper().endswith("_FILE") or is_reference(value):
        return False
    return bool(SECRET_NAME.search(name)) or bool(URL_CREDS.search(value))


def scan_env(env: list[str], source: str, location: str, severity: str) -> list[Finding]:
    out = []
    for i, item in enumerate(env):
        name, _, value = item.partition("=")
        if secret_like(name, value):
            kind = "url-credentials" if URL_CREDS.search(value) and not SECRET_NAME.search(name) else "secret-in-env"
            out.append(Finding(source, f"{location}[{i}]", kind, name, severity, f"{name}={redact(value)}"))
    return out


def scan_image_config(cfg: dict) -> list[Finding]:
    out = scan_env(cfg.get("config", {}).get("Env", []), "image-config", "config.Env", "HIGH")
    if cfg.get("history"):
        out += scan_history(cfg["history"])
    return out


def scan_docker_inspect(doc: Any) -> list[Finding]:
    containers = doc if isinstance(doc, list) else [doc]
    out: list[Finding] = []
    for c in containers:
        label = c.get("Name", "container").lstrip("/")
        out += scan_env(c.get("Config", {}).get("Env", []), "docker-inspect", f"{label}.Config.Env", "HIGH")
        for m in c.get("Mounts", []):
            if m.get("Type") == "bind" and SECRET_FILE.search(m.get("Source", "")):
                out.append(Finding("docker-inspect", f"{label}.Mounts", "secret-file-bind-mount", m["Source"], "MEDIUM",
                                   f"{m['Source']} -> {m['Destination']} (readable on the host by whoever can reach the file)"))
    return out


def scan_history(entries: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    added: dict[str, int] = {}
    for i, e in enumerate(entries):
        cmd = e.get("created_by") or e.get("CreatedBy") or ""
        loc = f"history[{i}]"
        m = re.search(r"\bENV\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", cmd)
        if m and secret_like(m.group(1), m.group(2)):
            out.append(Finding("image-history", loc, "secret-in-ENV-layer", m.group(1), "HIGH", f"ENV {m.group(1)}={redact(m.group(2))}"))
        p = BUILD_ARG_PREFIX.match(cmd)
        if p:
            for pair in p.group(1).split():
                n, _, v = pair.partition("=")
                if secret_like(n, v):
                    out.append(Finding("image-history", loc, "build-arg-secret", n, "HIGH", f"ARG {n}={redact(v)} (build args persist in history)"))
        u = URL_CREDS.search(cmd)
        if u:
            out.append(Finding("image-history", loc, "url-credentials", u.group(1), "HIGH", f"{u.group(1)}:{redact(u.group(2))}@..."))
        w = re.search(r"(?i)(echo|printf)\s+['\"]?([A-Za-z_]*(password|secret|token|key)[A-Za-z_]*)\s*=\s*([^\s'\">]+)", cmd)
        if w:
            out.append(Finding("image-history", loc, "secret-written-to-file", w.group(2), "HIGH", f"{w.group(2)}={redact(w.group(4))}"))
        c = re.search(r"\b(?:COPY|ADD)\b.*? in (\S+)", cmd)
        if c and SECRET_FILE.search(c.group(1)):
            added[c.group(1)] = i
            out.append(Finding("image-history", loc, "secret-file-copied", c.group(1), "HIGH", f"COPY of {c.group(1)} into the image"))
        r = re.search(r"\brm\s+(?:-\w+\s+)*(\S+)", cmd)
        if r and r.group(1) in added:
            out.append(Finding("image-history", loc, "deleted-but-still-in-layer", r.group(1), "MEDIUM",
                               f"{r.group(1)} was added in history[{added[r.group(1)]}]; removing it later does not remove it from that layer"))
    return out


def scan_compose(doc: dict) -> list[Finding]:
    out: list[Finding] = []
    for sname, svc in (doc.get("services") or {}).items():
        env = svc.get("environment", [])
        items = [f"{k}={v}" for k, v in env.items()] if isinstance(env, dict) else list(env)
        out += scan_env(items, "compose", f"services.{sname}.environment", "HIGH")
        if svc.get("env_file"):
            out.append(Finding("compose", f"services.{sname}.env_file", "env-file", str(svc["env_file"]), "LOW",
                               "env_file is expanded into the container environment: keep it out of git and prefer secrets"))
    return out


def scan_log(text: str) -> list[Finding]:
    out: list[Finding] = []
    for n, line in enumerate(text.splitlines(), start=1):
        for name, value in KV_IN_TEXT.findall(line):
            if secret_like(name, value):
                out.append(Finding("log", f"line {n}", "secret-in-log", name, "HIGH", f"{name}={redact(value)}"))
        for u in URL_CREDS.finditer(line):
            out.append(Finding("log", f"line {n}", "url-credentials-in-log", u.group(1), "HIGH", f"{u.group(1)}:{redact(u.group(2))}@..."))
        for b in BEARER.finditer(line):
            out.append(Finding("log", f"line {n}", "bearer-token-in-log", "Authorization", "HIGH", f"Bearer {redact(b.group(1))}"))
    return out


def make_proc_environ(env: list[str]) -> bytes:
    """What `cat /proc/<pid>/environ` returns: NUL-separated NAME=value pairs."""
    return b"\0".join(e.encode() for e in env) + b"\0"


def scan_proc_environ(data: bytes, pid: int = 1) -> list[Finding]:
    env = [x for x in data.decode(errors="replace").split("\0") if x]
    return scan_env(env, "proc-environ", f"/proc/{pid}/environ", "HIGH")


# ------------------------------------------------------------------ fixes: runtime injection
def runtime_injection(env: list[str]) -> tuple[list[str], dict[str, str]]:
    """Replace NAME=value secrets by NAME_FILE=/run/secrets/<name>. Returns (clean env, secrets to mount at run time)."""
    clean, to_mount = [], {}
    for item in env:
        name, _, value = item.partition("=")
        if secret_like(name, value):
            fname = name.lower()
            clean.append(f"{name}_FILE=/run/secrets/{fname}")
            to_mount[fname] = value
        else:
            clean.append(item)
    return clean, to_mount


def rewrite_compose(doc: dict) -> tuple[dict, list[str]]:
    """Move environment secrets to Compose `secrets:` (file-based) and point NAME_FILE at /run/secrets/<name>."""
    new = copy.deepcopy(doc)
    names: list[str] = []
    for svc in (new.get("services") or {}).values():
        env = svc.get("environment", [])
        as_dict = isinstance(env, dict)
        items = [f"{k}={v}" for k, v in env.items()] if as_dict else list(env)
        clean, mount = runtime_injection(items)
        if mount:
            svc["secrets"] = sorted(set(svc.get("secrets", [])) | set(mount))
            names += list(mount)
        svc["environment"] = dict(i.split("=", 1) for i in clean) if as_dict else clean
    if names:
        new["secrets"] = {n: {"file": f"./secrets/{n}.txt"} for n in sorted(set(names))}
    return new, sorted(set(names))


def read_secret(name: str, environ: dict[str, str], read_file: Callable[[str], str]) -> str:
    """App-side helper: prefer NAME_FILE, fall back to NAME (development only)."""
    if f"{name}_FILE" in environ:
        return read_file(environ[f"{name}_FILE"]).rstrip("\n")
    if name in environ:
        return environ[name]
    raise KeyError(f"{name} is not configured (set {name}_FILE)")


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEV[f.severity], f.source, f.location))


def render(findings: list[Finding]) -> str:
    return "\n".join(f"  [{f.severity:6}] {f.source:14} {f.location:28} {f.kind}: {f.evidence}" for f in sort_findings(findings))


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_yaml(path: str | Path) -> Any:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))
