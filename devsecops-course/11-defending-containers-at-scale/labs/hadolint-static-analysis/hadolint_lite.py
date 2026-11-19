"""A tiny Hadolint-style Dockerfile linter with SARIF output.

Rule IDs follow the Hadolint naming style (DL3xxx / DL4xxx). The exact meaning and
numbering of the real rules change between releases: verify at
https://github.com/hadolint/hadolint . DSO-xxx rules are this lab's own.
The repo's simpler linter is 06-ai-devsecops/docker/lab/dockerfile_lint.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    level: str  # error | warning | info
    line: int
    message: str


def parse(text: str) -> list[tuple[int, str, str]]:
    """Return (line_no, INSTRUCTION, args), joining backslash continuations."""
    out, buf, start = [], "", 0
    for no, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not buf and (not s or s.startswith("#")):
            continue
        if not buf:
            start = no
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        ins, _, args = buf.partition(" ")
        out.append((start, ins.upper(), args.strip()))
        buf = ""
    return out


SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)", re.I)


def lint(text: str) -> list[Finding]:
    ins = parse(text)
    f: list[Finding] = []
    last_user = None
    saw_healthcheck = False
    saw_pipefail = False
    for no, op, args in ins:
        if op == "SHELL" and "pipefail" in args:
            saw_pipefail = True
        if op == "FROM":
            img = re.split(r"\s+as\s+", args, flags=re.I)[0].split()[0]
            if img != "scratch" and "@sha256:" not in img:
                name = img.rsplit("/", 1)[-1]
                if ":" not in name:
                    f.append(Finding("DL3006", "warning", no, f"Always tag the version of an image explicitly ({img})"))
                elif name.endswith(":latest"):
                    f.append(Finding("DL3007", "warning", no, "Using latest is prone to errors; pin the version"))
        elif op == "USER":
            last_user = args.split()[0]
        elif op == "HEALTHCHECK":
            saw_healthcheck = True
        elif op == "ADD":
            if not re.search(r"https?://|\.(tar|tgz|gz)\b", args):
                f.append(Finding("DL3020", "error", no, "Use COPY instead of ADD for files and folders"))
            elif "http" in args:
                f.append(Finding("DSO-003", "warning", no, "ADD from a URL: no checksum verification"))
        elif op == "ENV" and SECRET_NAME.search(args.split("=")[0].split()[0]):
            f.append(Finding("DSO-001", "error", no, "Secret-looking ENV persists in image layers and `docker history`"))
        elif op in ("CMD", "ENTRYPOINT"):
            if not args.startswith("["):
                f.append(Finding("DL3025", "warning", no, f"Use arguments JSON notation for {op}"))
        elif op == "RUN":
            if re.search(r"\bcd\s", args):
                f.append(Finding("DL3003", "warning", no, "Use WORKDIR to switch to a directory"))
            if "apt-get install" in args:
                if not re.search(r"=\d", args):
                    f.append(Finding("DL3008", "warning", no, "Pin versions in apt-get install"))
                if "--no-install-recommends" not in args:
                    f.append(Finding("DL3015", "info", no, "Avoid additional packages by --no-install-recommends"))
                if "/var/lib/apt/lists" not in args:
                    f.append(Finding("DL3009", "info", no, "Delete the apt-get lists after installing"))
            if "pip install" in args and "--no-cache-dir" not in args:
                f.append(Finding("DL3042", "warning", no, "Avoid cache directory with pip install --no-cache-dir"))
            if re.search(r"(curl|wget)[^|]*\|\s*(sh|bash)", args):
                f.append(Finding("DSO-002", "error", no, "Piping a download into a shell: pin and verify a checksum"))
            elif "|" in args and not saw_pipefail:
                f.append(Finding("DL4006", "warning", no, "Set the SHELL option -o pipefail before RUN with a pipe"))
    if last_user is None or last_user in ("root", "0"):
        f.append(Finding("DL3002", "warning", ins[-1][0] if ins else 1, "Last USER should not be root"))
    if not saw_healthcheck:
        f.append(Finding("DSO-004", "info", 1, "No HEALTHCHECK (Dockle CIS-DI-0006 style)"))
    return sorted(f, key=lambda x: (x.line, x.rule))


_SARIF_LEVEL = {"error": "error", "warning": "warning", "info": "note"}


def to_sarif(findings: list[Finding], uri: str = "Dockerfile") -> dict:
    rules = sorted({x.rule for x in findings})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "hadolint-lite", "rules": [{"id": r} for r in rules]}},
            "results": [{
                "ruleId": x.rule,
                "level": _SARIF_LEVEL[x.level],
                "message": {"text": x.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": x.line}}}],
            } for x in findings],
        }],
    }


def gate(findings: list[Finding], fail_on: str = "error") -> bool:
    """True = pipeline passes. fail_on is the lowest level that fails the build."""
    order = {"info": 0, "warning": 1, "error": 2}
    return not any(order[x.level] >= order[fail_on] for x in findings)
