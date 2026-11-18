"""A small Dockerfile linter for model-serving images.

    python dockerfile_lint.py path/to/Dockerfile [--dockerignore path] [--disable DF-012]

It parses the Dockerfile into stages and instructions, then runs rules with IDs.
Most rules look at every stage; rules about what ships (USER, build tools) look only
at the FINAL stage, because earlier stages are thrown away by a multi-stage build.

This is a teaching tool. In a real pipeline use hadolint (Dockerfile rules), Trivy or
Grype (CVEs in the built image), and ModelScan (model files). The ideas are the same.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
SECRET_VALUE = re.compile(r"(sk-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})")
SECRET_FILE = re.compile(r"(^|/)(\.env(\..*)?|.*\.pem|.*\.key|id_rsa.*|id_ed25519.*|\.netrc|\.npmrc|\.pypirc"
                         r"|credentials(\.json)?|\.aws(/.*)?|\.git-credentials|kubeconfig)$", re.I)
PICKLE_MODEL = re.compile(r"\.(pkl|pickle|pt|pth|bin|ckpt|joblib)$", re.I)
BUILD_TOOLS = {"build-essential", "gcc", "g++", "make", "cmake", "git", "clang"}
PIPE_TO_SHELL = re.compile(r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    line: int
    message: str


@dataclass
class Instruction:
    line: int
    keyword: str
    args: str


@dataclass
class Stage:
    image: str
    name: str | None
    line: int
    instructions: list[Instruction] = field(default_factory=list)


@dataclass
class Dockerfile:
    stages: list[Stage]
    dockerignore: str | None = None  # contents of .dockerignore, if one exists

    @property
    def final(self) -> Stage:
        return self.stages[-1]

    def all(self) -> Iterator[tuple[Stage, Instruction]]:
        for stage in self.stages:
            for ins in stage.instructions:
                yield stage, ins


def parse(text: str, dockerignore: str | None = None) -> Dockerfile:
    """Turn Dockerfile text into stages. Handles comments and '\\' line continuations."""
    logical: list[tuple[int, str]] = []
    buf, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if buf and line.startswith("#"):
            continue  # comment lines inside a continuation are ignored by Docker too
        if not buf:
            start = number
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical.append((start, buf + line))
        buf = ""
    if buf:
        logical.append((start, buf))

    stages: list[Stage] = []
    for number, line in logical:
        keyword, _, args = line.partition(" ")
        keyword, args = keyword.upper(), args.strip()
        if keyword == "FROM":
            parts = [p for p in args.split() if not p.startswith("--")]
            name = parts[2] if len(parts) >= 3 and parts[1].upper() == "AS" else None
            stages.append(Stage(image=parts[0] if parts else "", name=name, line=number))
        elif stages:
            stages[-1].instructions.append(Instruction(number, keyword, args))
    if not stages:
        raise ValueError("no FROM instruction found")
    return Dockerfile(stages, dockerignore)


# --------------------------------------------------------------------------- rules

Rule = Callable[[Dockerfile], Iterator[tuple[int, str]]]
RULES: dict[str, tuple[str, str, Rule]] = {}


def rule(rule_id: str, severity: str, title: str) -> Callable[[Rule], Rule]:
    def register(fn: Rule) -> Rule:
        RULES[rule_id] = (severity, title, fn)
        return fn
    return register


def external_images(df: Dockerfile) -> Iterator[Stage]:
    seen: set[str] = set()
    for stage in df.stages:
        if stage.image.lower() != "scratch" and stage.image not in seen:
            yield stage
        if stage.name:
            seen.add(stage.name)


@rule("DF-001", "HIGH", "Base image not pinned by digest")
def pin_digest(df: Dockerfile):
    for stage in external_images(df):
        if not DIGEST.search(stage.image):
            yield stage.line, f"'{stage.image}' can change under you; pin it as image@sha256:<digest>"


@rule("DF-002", "MEDIUM", "Base image uses 'latest' or no tag")
def latest_tag(df: Dockerfile):
    for stage in external_images(df):
        ref = stage.image.split("@")[0]
        tag = ref.rsplit(":", 1)[1] if ":" in ref.rsplit("/", 1)[-1] else None
        if tag in (None, "latest") and not DIGEST.search(stage.image):
            yield stage.line, f"'{stage.image}' resolves to 'latest'"


@rule("DF-003", "HIGH", "Final image runs as root")
def runs_as_root(df: Dockerfile):
    users = [i for i in df.final.instructions if i.keyword == "USER"]
    if not users:
        yield df.final.line, "no USER in the final stage: the process runs as root (UID 0)"
    elif users[-1].args.split(":")[0] in {"root", "0"}:
        yield users[-1].line, "last USER is root"


@rule("DF-004", "CRITICAL", "Secret in ENV or ARG")
def secret_env_arg(df: Dockerfile):
    for _, ins in df.all():
        if ins.keyword not in {"ENV", "ARG"}:
            continue
        pairs = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)(?:=(\S*))?", ins.args)
        if ins.keyword == "ENV" and "=" not in ins.args:  # legacy form: ENV KEY value
            key, _, value = ins.args.partition(" ")
            pairs = [(key, value)]
        for key, value in pairs:
            if SECRET_NAME.search(key) or SECRET_VALUE.search(value or ""):
                yield ins.line, f"{ins.keyword} {key}: values are kept in image metadata/history; use --mount=type=secret"


@rule("DF-005", "HIGH", "Secret file copied into the image")
def secret_files(df: Dockerfile):
    for _, ins in df.all():
        if ins.keyword in {"COPY", "ADD"}:
            sources = [s for s in ins.args.split() if not s.startswith("--")][:-1]
            for src in sources:
                if SECRET_FILE.search(src.rstrip("/")):
                    yield ins.line, f"'{src}' looks like a credential file; it stays in a layer even if deleted later"


@rule("DF-006", "MEDIUM", "ADD downloads a remote URL without verification")
def add_remote(df: Dockerfile):
    for _, ins in df.all():
        if ins.keyword == "ADD" and re.search(r"https?://", ins.args) and "--checksum=" not in ins.args:
            yield ins.line, "use ADD --checksum=sha256:<hash> <url>, or download and verify in a build stage"


@rule("DF-007", "HIGH", "Remote script piped to a shell")
def pipe_to_shell(df: Dockerfile):
    for _, ins in df.all():
        if ins.keyword == "RUN" and PIPE_TO_SHELL.search(ins.args):
            yield ins.line, "curl | sh runs whatever the server sends; download, verify a checksum, then run"


@rule("DF-008", "MEDIUM", "Build tools in the final image")
def build_tools(df: Dockerfile):
    for ins in df.final.instructions:
        if ins.keyword == "RUN" and re.search(r"\b(apt-get|apt|apk|yum|dnf)\b.*\b(install|add)\b", ins.args):
            found = sorted(BUILD_TOOLS & set(re.split(r"[\s=]+", ins.args)))
            if found:
                yield ins.line, f"{found} ship to production; build in an earlier stage (multi-stage build)"


def pip_commands(text: str) -> Iterator[list[str]]:
    for segment in re.split(r"&&|;|\|\|", text):
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        for i in range(len(tokens) - 1):
            if tokens[i].endswith("pip") and tokens[i + 1] == "install":
                yield tokens[i + 2:]


@rule("DF-009", "MEDIUM", "Python packages not pinned / not hash-checked")
def unpinned_pip(df: Dockerfile):
    for _, ins in df.all():
        if ins.keyword != "RUN":
            continue
        for args in pip_commands(ins.args):
            if any(a in {"-r", "--requirement"} or a.startswith("--requirement=") for a in args):
                if "--require-hashes" not in args:
                    yield ins.line, "requirements installed without --require-hashes"
                continue
            loose = [a for a in args if not a.startswith("-") and "==" not in a and a not in {".", "-e"}
                     and not a.startswith(("http://", "https://", "/", "./"))]
            if loose:
                yield ins.line, f"unpinned packages {loose}"


@rule("DF-010", "HIGH", "Extra package index (dependency confusion)")
def extra_index(df: Dockerfile):
    for _, ins in df.all():
        if ins.keyword in {"RUN", "ENV", "ARG"} and re.search(r"--extra-index-url|PIP_EXTRA_INDEX_URL", ins.args):
            yield ins.line, "pip may pick a public package with the same name as your internal one"


@rule("DF-011", "MEDIUM", "Pickle-format model file in the image")
def pickle_models(df: Dockerfile):
    for _, ins in df.all():
        if ins.keyword in {"COPY", "ADD"} and not any(a.startswith("--from=") for a in ins.args.split()):
            for src in [s for s in ins.args.split() if not s.startswith("--")][:-1]:
                if PICKLE_MODEL.search(src):
                    yield ins.line, f"'{src}' can run code when loaded; convert to safetensors and scan it"


@rule("DF-012", "MEDIUM", "Whole build context copied with no .dockerignore")
def copy_all(df: Dockerfile):
    if df.dockerignore is not None:
        return
    for _, ins in df.all():
        if ins.keyword in {"COPY", "ADD"}:
            sources = [s for s in ins.args.split() if not s.startswith("--")][:-1]
            if any(s in {".", "./", "*"} for s in sources):
                yield ins.line, "COPY . copies .git, .env, notebooks and caches unless .dockerignore excludes them"


# --------------------------------------------------------------------------- engine

def lint(text: str, *, dockerignore: str | None = None,
         disabled: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    df = parse(text, dockerignore)
    findings = []
    for rule_id, (severity, _title, fn) in sorted(RULES.items()):
        if rule_id not in disabled:
            findings += [Finding(rule_id, severity, line, msg) for line, msg in fn(df)]
    return sorted(findings, key=lambda f: (f.line, f.rule_id))


def lint_file(path: str | Path, **kw) -> list[Finding]:
    path = Path(path)
    ignore = path.with_name(".dockerignore")
    if "dockerignore" not in kw:
        kw["dockerignore"] = ignore.read_text(encoding="utf-8") if ignore.exists() else None
    return lint(path.read_text(encoding="utf-8"), **kw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint a model-serving Dockerfile.")
    parser.add_argument("dockerfile")
    parser.add_argument("--disable", action="append", default=[])
    parser.add_argument("--fail-on", default="HIGH", choices=list(SEVERITY))
    args = parser.parse_args(argv)
    findings = lint_file(args.dockerfile, disabled=set(args.disable))
    for f in findings:
        print(f"line {f.line:3}  {f.severity:8} {f.rule_id}  {f.message}")
    failed = any(SEVERITY[f.severity] >= SEVERITY[args.fail_on] for f in findings)
    print(f"\n{'FAIL' if failed else 'PASS'}: {len(findings)} finding(s), fail-on={args.fail_on}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
