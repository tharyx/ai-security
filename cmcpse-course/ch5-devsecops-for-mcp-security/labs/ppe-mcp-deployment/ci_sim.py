"""A simulated CI system for an MCP server repo, with a fake shell. NOTHING REAL RUNS.

What it models (the parts that matter for Poisoned Pipeline Execution):
  * which pipeline file runs: the one on the PR branch, or the one on the protected base branch
  * which secrets a run can see: all runs, or only trusted (post-merge, approved) deploy steps
  * how untrusted text (a tool description) reaches a command: pasted into the command line
    (`${{ tool_description }}`, like GitHub's expression templating) or passed in an env variable
  * whether config hooks (a `postinstall` script) run during the build
  * whether the runner can reach the internet (egress allowlist)
  * a merge gate: protected paths need an approval from a code owner who is not the author

The fake shell understands: echo, make, sh, exfil, publish, deploy, mcp-build, scan-descriptions.
`exfil NAME host` is the attacker's command: it appends the value of $NAME to a list. That list
is the "attacker server". The secret is a canary from make_canary().
"""

from __future__ import annotations

import importlib.util
import json
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
PIPELINE_LAB = HERE.parent / "mcp-cicd-pipeline" / "pipeline_runner.py"


def _load_pipeline_runner():
    spec = importlib.util.spec_from_file_location("ppe_pipeline_runner", PIPELINE_LAB)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass
class PullRequest:
    changes: dict
    author: str = "mallory"
    from_fork: bool = False


@dataclass
class Platform:
    """The CI platform settings. VULNERABLE and SECURE below are the two ends of the lab."""

    name: str
    pipeline_file: str
    pipeline_from_base: bool
    secrets_on_pr_runs: bool
    ignore_scripts: bool
    egress_allowlist: frozenset | None
    protected_paths: tuple = ()
    codeowners: tuple = ()


VULNERABLE = Platform("vulnerable", "vulnerable-pipeline.yml", False, True, False, None)
SECURE = Platform(
    "secure", "secure-pipeline.yml", True, False, True,
    frozenset({"registry.example.internal"}),
    protected_paths=(".ci/", "scripts/", "Makefile", "mcp-server.config.json", "mcp-manifest.json"),
    codeowners=("secops-lead", "mcp-platform-owner"),
)


@dataclass
class RunResult:
    log: list = field(default_factory=list)
    sink: list = field(default_factory=list)       # what reached the attacker
    published: list = field(default_factory=list)
    deployed: list = field(default_factory=list)
    failed: bool = False
    skipped: list = field(default_factory=list)

    def leaked(self, canary: str) -> bool:
        return any(canary in value for _, value in self.sink)


def base_repo(platform: Platform) -> dict:
    return {
        ".ci/pipeline.yml": (HERE / "workflows" / platform.pipeline_file).read_text(encoding="utf-8"),
        "Makefile": "test:\n\techo running unit tests\n",
        "scripts/deploy.sh": "echo packaging server\ndeploy\n",
        "mcp-server.config.json": json.dumps({"name": "notes-mcp", "scripts": {"postinstall": "echo compiling"}}),
        "mcp-manifest.json": json.dumps({"tools": [{"name": "read_note", "description": "Read a note by name.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}}}]}),
        "src/server.py": "print('notes mcp server v1')",
    }


class FakeShell:
    def __init__(self, files: dict, env: dict, result: RunResult, platform: Platform, depth: int = 0):
        self.files, self.env, self.result, self.platform, self.depth = files, env, result, platform, depth

    # ---- shell-like expansion: command substitution first, then variables, in ONE pass each
    def run_line(self, line: str) -> int:
        if self.depth > 5:
            return 1
        line = line.strip().lstrip("@").strip()
        if not line or line.startswith("#"):
            return 0
        pattern = re.compile(r"\$\(([^()]*)\)")
        while pattern.search(line):
            line = pattern.sub(lambda m: self._capture(m.group(1)), line)
        line = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", lambda m: self.env.get(m.group(1), ""), line)
        try:
            argv = shlex.split(line)
        except ValueError:
            self.result.log.append(f"syntax error: {line[:60]}")
            return 2
        return self.dispatch(argv)

    def _capture(self, inner: str) -> str:
        child = FakeShell(self.files, self.env, self.result, self.platform, self.depth + 1)
        child.run_line(inner)
        return ""

    def dispatch(self, argv: list) -> int:
        cmd, args, log = argv[0], argv[1:], self.result.log
        if cmd == "echo":
            log.append(" ".join(args))
            return 0
        if cmd == "make":
            return self._make(args[0] if args else "all")
        if cmd == "sh":
            text = self.files.get(args[0])
            if text is None:
                log.append(f"sh: {args[0]}: not found")
                return 127
            return max([self.run_line(row) for row in text.splitlines()] or [0])
        if cmd == "exfil":
            name, host = args[0], args[1]
            value = self.env.get(name, "")
            allow = self.platform.egress_allowlist
            if allow is not None and host not in allow:
                log.append(f"BLOCKED egress to {host}")
                return 1
            if value:
                self.result.sink.append((host, value))
            else:
                log.append(f"exfil: {name} is empty in this run")
            return 0
        if cmd == "publish":
            self.result.published.append(args[args.index("--description") + 1] if "--description" in args else "")
            log.append("published tool docs")
            return 0
        if cmd == "deploy":
            if "DEPLOY_TOKEN" not in self.env:
                log.append("deploy: no DEPLOY_TOKEN, refusing")
                return 1
            self.result.deployed.append("notes-mcp")
            log.append("deployed notes-mcp")
            return 0
        if cmd == "mcp-build":
            return self._build()
        if cmd == "scan-descriptions":
            return self._scan_descriptions()
        log.append(f"{cmd}: command not found")
        return 127

    def _make(self, target: str) -> int:
        lines, active = [], False
        for row in self.files.get("Makefile", "").splitlines():
            if row.startswith(f"{target}:"):
                active = True
            elif row and not row.startswith("\t"):
                active = False
            elif active:
                lines.append(row)
        return max([self.run_line(row) for row in lines] or [0])

    def _build(self) -> int:
        config = json.loads(self.files.get("mcp-server.config.json", "{}"))
        hook = config.get("scripts", {}).get("postinstall")
        if hook and not self.platform.ignore_scripts:
            self.result.log.append("running postinstall hook")
            return self.run_line(hook)
        if hook:
            self.result.log.append("postinstall hook skipped (ignore_scripts)")
        return 0

    def _scan_descriptions(self) -> int:
        runner = _load_pipeline_runner()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "mcp-manifest.json").write_text(self.files["mcp-manifest.json"], encoding="utf-8")
            findings = runner.stage_tool_descriptions(Path(tmp), {})
        findings = findings + self._shell_syntax_in_descriptions()
        for finding in findings:
            self.result.log.append(f"description scan: {finding}")
        return 1 if findings else 0

    def _shell_syntax_in_descriptions(self) -> list:
        runner = _load_pipeline_runner()
        manifest = json.loads(self.files["mcp-manifest.json"])
        return [
            runner.PFinding("tool-descriptions", "high", "DESC-SHELL", f"{t['name']}: shell syntax in description")
            for t in manifest.get("tools", [])
            if re.search(r"\$\(|`|;\s*\w+", t.get("description", ""))
        ]


def _expand_expressions(text: str, context: dict) -> str:
    """Textual `${{ name }}` expansion BEFORE the shell sees the line (the root of script injection)."""
    return re.sub(r"\$\{\{\s*([\w.]+)\s*\}\}", lambda m: str(context.get(m.group(1), "")), text)


def run_pipeline(platform: Platform, repo: dict, pr: PullRequest | None, secrets: dict, event: str = "pull_request",
                 approved_environments: frozenset = frozenset()) -> RunResult:
    """Run the pipeline the way `platform` would for this event."""
    head = dict(repo)
    if pr:
        head.update(pr.changes)
    pipeline_text = repo[".ci/pipeline.yml"] if platform.pipeline_from_base else head[".ci/pipeline.yml"]
    pipeline = yaml.safe_load(pipeline_text)
    result = RunResult()
    trusted_secrets = event == "push" or platform.secrets_on_pr_runs
    manifest = json.loads(head["mcp-manifest.json"])
    context = {"tool_description": manifest["tools"][0]["description"]}
    for stage in pipeline["stages"]:
        if stage.get("only_event") and stage["only_event"] != event:
            result.skipped.append(stage["name"])
            result.log.append(f"[{stage['name']}] skipped (only on {stage['only_event']})")
            continue
        if stage.get("environment") and stage["environment"] not in approved_environments:
            result.skipped.append(stage["name"])
            result.log.append(f"[{stage['name']}] waiting for approval of environment '{stage['environment']}'")
            continue
        env = {}
        if trusted_secrets:
            for name in list(pipeline.get("env_secrets", [])) + list(stage.get("secrets", [])):
                env[name] = secrets[name]
        for key, value in (stage.get("env") or {}).items():
            env[key] = _expand_expressions(str(value), context)
        shell = FakeShell(head, env, result, platform)
        for line in stage["run"]:
            status = shell.run_line(_expand_expressions(line, context))
            if status != 0:
                result.failed = True
                result.log.append(f"[{stage['name']}] FAILED")
                return result
        result.log.append(f"[{stage['name']}] ok")
    return result


def merge_allowed(platform: Platform, pr: PullRequest, approved_by: tuple = ()) -> tuple[bool, str]:
    """Branch protection with CODEOWNERS: protected paths need an approval from a code owner who is not the author."""
    touched = [p for p in pr.changes if any(p == prot or p.startswith(prot) for prot in platform.protected_paths)]
    if not touched:
        return True, "no protected paths touched"
    valid = [a for a in approved_by if a in platform.codeowners and a != pr.author]
    if valid:
        return True, f"approved by {valid[0]} for {touched}"
    return False, f"needs a code owner approval for {touched}"
