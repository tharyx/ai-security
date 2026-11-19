"""Minimise container misconfigurations: lint the Dockerfile, then generate hardened run settings.

Reuses (does not copy):
  - 06-ai-devsecops/docker/lab/dockerfile_lint.py   the 12-rule Dockerfile linter
  - ../docker-commands/run_assess.py                 the `docker run` assessor from this chapter
"""
from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]


def load_by_path(path: Path, unique: str):
    if unique in sys.modules:
        return sys.modules[unique]
    spec = importlib.util.spec_from_file_location(unique, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)
    return mod


dockerfile_lint = load_by_path(REPO / "06-ai-devsecops" / "docker" / "lab" / "dockerfile_lint.py", "csse3_dockerfile_lint")
run_assess = load_by_path(HERE.parent / "docker-commands" / "run_assess.py", "csse3_run_assess")

FIXES = {
    "DF-001": "FROM image@sha256:<digest> (let Renovate or Dependabot bump it)",
    "DF-002": "use a version tag, then pin the digest",
    "DF-003": "add a numeric USER (for example 10001) in the final stage",
    "DF-004": "remove ENV/ARG secrets; use RUN --mount=type=secret",
    "DF-005": "do not COPY credential files; add them to .dockerignore",
    "DF-006": "ADD --checksum=sha256:<hash> or download and verify in a build stage",
    "DF-007": "download, verify the checksum, then run; never curl | sh",
    "DF-008": "move compilers and git to a build stage (multi-stage)",
    "DF-009": "pip install --require-hashes -r requirements.lock",
    "DF-010": "use one trusted --index-url",
    "DF-011": "convert models to safetensors",
    "DF-012": "add a .dockerignore (.git, .env, node_modules)",
}


def lint_with_fixes(dockerfile_text: str, dockerignore: str | None = None) -> list[tuple[str, str, int, str, str]]:
    return [(f.rule_id, f.severity, f.line, f.message, FIXES.get(f.rule_id, "see rule")) for f in
            dockerfile_lint.lint(dockerfile_text, dockerignore=dockerignore)]


@dataclass
class RunProfile:
    image: str
    port: int | None = None
    writable_dirs: list[str] = field(default_factory=list)   # become tmpfs mounts
    caps: list[str] = field(default_factory=list)            # capabilities the app really needs
    user: str = "10001:10001"
    memory: str = "256m"
    pids: int = 100


def harden_run(p: RunProfile) -> str:
    parts = ["docker run -d", "--read-only", f"--user {p.user}", "--cap-drop ALL"]
    parts += [f"--cap-add {c}" for c in p.caps]
    parts += ["--security-opt no-new-privileges", f"--memory {p.memory}", f"--pids-limit {p.pids}"]
    parts += [f"--tmpfs {d}" for d in (p.writable_dirs or ["/tmp"])]
    if p.port:
        parts.append(f"-p 127.0.0.1:{p.port}:{p.port}")
    parts.append(p.image)
    return " ".join(parts)


def harden_compose(p: RunProfile) -> dict:
    svc = {
        "image": p.image, "read_only": True, "user": p.user, "cap_drop": ["ALL"], "cap_add": p.caps,
        "security_opt": ["no-new-privileges:true"], "mem_limit": p.memory, "pids_limit": p.pids,
        "tmpfs": p.writable_dirs or ["/tmp"],
    }
    if p.port:
        svc["ports"] = [f"127.0.0.1:{p.port}:{p.port}"]
    return {"services": {"app": svc}}


def assess_text(command: str):
    return run_assess.assess(run_assess.parse_run(command))
