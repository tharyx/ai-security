"""Dockerfile best-practice checker and a cache-friendliness comparison.

Reuses the parser from ../dockerfile-build. This is a small teaching linter; the repo's fuller one is
06-ai-devsecops/docker/lab/dockerfile_lint.py and the real tool is Hadolint (see real-tools).
"""
from __future__ import annotations

import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load_builder():
    path = _HERE.parent / "dockerfile-build" / "dockerfile.py"
    name = "dso_ch09_dockerfile_builder"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


df = _load_builder()
SECRET_NAME = re.compile(r"(PASS(WORD)?|SECRET|TOKEN|API_?KEY)", re.I)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    line: int
    message: str


def lint(text: str) -> list[Finding]:
    ins = df.parse(text)
    out: list[Finding] = []
    stages = df.stages(ins)
    last = stages[-1]
    for st in stages:
        base = st.base
        if base != "scratch" and "@sha256:" not in base:
            tag = base.split(":", 1)[1] if ":" in base else "latest"
            if tag == "latest":
                out.append(Finding("DF-001", "HIGH", 0, f"base image {base} is not pinned (latest): builds are not reproducible"))
            elif "@" not in base:
                out.append(Finding("DF-002", "LOW", 0, f"base image {base} pinned by tag only: pin the digest for supply chain safety"))
    for i in ins:
        if i.cmd == "ENV" and SECRET_NAME.search(i.args.split("=")[0].split()[0]):
            out.append(Finding("DF-003", "CRITICAL", i.line, "secret in ENV: it stays in the image config and history for everyone who pulls"))
        if i.cmd == "ADD" and re.search(r"https?://", i.args):
            out.append(Finding("DF-004", "MEDIUM", i.line, "ADD from a URL: unverified download; use COPY plus a checksum-verified RUN"))
        if i.cmd == "RUN" and re.search(r"(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh", i.args):
            out.append(Finding("DF-005", "HIGH", i.line, "curl | sh: executes whatever the server returns at build time"))
        if i.cmd == "RUN" and "apt-get install" in i.args and "--no-install-recommends" not in i.args:
            out.append(Finding("DF-006", "LOW", i.line, "apt-get install without --no-install-recommends: larger image, more CVEs"))
        if i.cmd == "RUN" and "apt-get install" in i.args and "update" not in i.args:
            out.append(Finding("DF-007", "LOW", i.line, "apt-get install without update in the same RUN: stale cache layer"))
        if i.cmd == "CMD" and not i.args.startswith("["):
            out.append(Finding("DF-008", "LOW", i.line, "shell-form CMD: runs under /bin/sh -c and does not receive signals; use exec form"))
    users = [i for i in last.instructions if i.cmd == "USER"]
    if not users or users[-1].args.strip() in ("root", "0"):
        out.append(Finding("DF-009", "HIGH", 0, "final stage runs as root: add a non-root USER"))
    if not any(i.cmd == "HEALTHCHECK" for i in last.instructions):
        out.append(Finding("DF-010", "LOW", 0, "no HEALTHCHECK: the orchestrator cannot tell a hung container from a healthy one"))
    # cache order: COPY of the whole context before dependency install
    seen_copy_all = False
    for i in last.instructions:
        if i.cmd == "COPY" and re.match(r"(--\S+\s+)*\.\s", i.args + " "):
            seen_copy_all = True
        if i.cmd == "RUN" and seen_copy_all and re.search(r"pip install|npm (ci|install)", i.args):
            out.append(Finding("DF-011", "LOW", i.line, "dependencies installed after COPY . : every source edit re-installs them; copy the manifest first"))
            break
    return sorted(out, key=lambda f: (["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f.severity), f.rule))


def score(findings: list[Finding]) -> int:
    w = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 3, "LOW": 1}
    return sum(w[f.severity] for f in findings)


def rebuild_cost(text: str, context: dict[str, int], edited_file: str) -> dict:
    """Edit one source file and report how many layers (and KB) are rebuilt."""
    cache: set[str] = set()
    first = df.build(text, context, cache)
    changed = dict(context)
    changed[edited_file] = changed.get(edited_file, 1) + 1
    second = df.build(text, changed, cache)
    rebuilt = [l for l in second["layers"][1:] if not l.cached]
    return {"layers": len(second["layers"]) - 1, "rebuilt": len(rebuilt), "rebuilt_kb": sum(l.size_kb for l in rebuilt),
            "first_size_kb": first["size_kb"]}
