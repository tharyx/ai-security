"""A local runner for the MCP security pipeline: the same stages the GitHub Actions fixture runs.

Stages (each returns findings; the policy gate decides which ones break the build):
  sast               MCP-specific static rules on the server source   (lab: sast-vulnerable-mcp-server)
  secrets            regex + entropy secret scan of the whole project
  deps               dependency audit: pinned versions + local advisory file
  tool-descriptions  poisoning patterns in tool descriptions and schemas
  manifest-pin       tool names/descriptions/schemas versus the approved lock file
  policy-gate        applies mcp-policy.yaml: severity threshold, required stages, approvals

Break-build rules: any blocking finding, a missing required stage, or a stage that crashes
(fail closed) gives exit code 1.

Usage:
  python pipeline_runner.py --project fixtures/project-bad [--pr fixtures/project-bad/pr.json]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SAST_DIR = HERE.parent / "sast-vulnerable-mcp-server"
DEFAULT_POLICY = HERE / "policy" / "mcp-policy.yaml"
ADVISORIES = HERE / "fixtures" / "advisories.json"
SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@dataclass
class PFinding:
    stage: str
    severity: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.code}: {self.message}"


@dataclass
class StageResult:
    name: str
    findings: list = field(default_factory=list)
    error: str = ""

    @property
    def status(self) -> str:
        return "error" if self.error else ("findings" if self.findings else "clean")


# ------------------------------------------------------------------ helpers
def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def version_tuple(version: str) -> tuple:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def load_policy(path: str | Path = DEFAULT_POLICY) -> dict:
    policy = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(policy, dict):
        raise ValueError("policy must be a mapping")
    for key in ("block_on_severity", "required_stages", "approvals"):
        if key not in policy:
            raise ValueError(f"policy is missing '{key}'")
    if policy["block_on_severity"] not in SEVERITY:
        raise ValueError("unknown severity in block_on_severity")
    return policy


def description_fingerprint(tool: dict) -> str:
    """Hash of everything the model reads about a tool: description plus the schema."""
    return sha256_text(json.dumps({"d": tool.get("description", ""), "s": tool.get("inputSchema", {})}, sort_keys=True))


# ------------------------------------------------------------------ stages
def stage_sast(project: Path, ctx: dict) -> list[PFinding]:
    sast = _load(SAST_DIR / "mcp_sast.py", "pipeline_mcp_sast")
    server_dir = project / "server"
    findings = sast.scan_tree(server_dir, include_secrets=False) if server_dir.exists() else []
    return [PFinding("sast", f.severity, f"SAST-{f.rule}", f"{f.file}:{f.line} {f.message}") for f in findings]


def stage_secrets(project: Path, ctx: dict) -> list[PFinding]:
    secret_scan = _load(SAST_DIR / "secret_scan.py", "pipeline_secret_scan")
    return [PFinding("secrets", "high", "SECRET", str(s)) for s in secret_scan.scan_tree(project)]


def stage_deps(project: Path, ctx: dict) -> list[PFinding]:
    findings = []
    advisories = json.loads(ADVISORIES.read_text(encoding="utf-8"))
    lock = project / "requirements.lock"
    if not lock.exists():
        return [PFinding("deps", "high", "DEP-NOLOCK", "no requirements.lock: dependencies are not pinned")]
    for raw in lock.read_text(encoding="utf-8").splitlines():
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==([\w.]+)", line)
        if not match:
            findings.append(PFinding("deps", "high", "DEP-UNPINNED", f"'{line.split()[0]}' is not pinned with =="))
            continue
        name, version = match.groups()
        for adv in advisories:
            if adv["package"] == name and version_tuple(version) < version_tuple(adv["fixed"]):
                findings.append(PFinding("deps", adv["severity"], "DEP-ADVISORY", f"{name}=={version}: {adv['id']} {adv['summary']} (fixed in {adv['fixed']})"))
    return findings


POISON_PATTERNS = [
    (r"<\s*/?\s*(important|system|instructions?|secret)\s*>", "hidden instruction tag"),
    (r"ignore (all )?(previous|prior|above) (instructions|rules)", "instruction override"),
    (r"do not (tell|mention|inform|show)[^.]{0,40}user", "concealment from the user"),
    (r"(~|/home/\w+)/\.ssh|id_rsa|\.aws/credentials|\.env\b|/etc/passwd", "sensitive file reference"),
    (r"before (using|calling|running) (this|any) tool[^.]{0,60}(read|send|include|call)", "pre-call side instruction"),
    (r"https?://", "URL inside a description"),
]
INVISIBLE = re.compile("[​‌‍⁠‪-‮⁦-⁩﻿]")
MAX_DESCRIPTION = 1200


def _texts(tool: dict):
    yield "description", tool.get("description", "")
    for pname, spec in tool.get("inputSchema", {}).get("properties", {}).items():
        yield f"param {pname}", spec.get("description", "")


def stage_tool_descriptions(project: Path, ctx: dict) -> list[PFinding]:
    manifest = json.loads((project / "mcp-manifest.json").read_text(encoding="utf-8"))
    findings = []
    for tool in manifest.get("tools", []):
        for where, text in _texts(tool):
            for pattern, label in POISON_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(PFinding("tool-descriptions", "high", "DESC-POISON", f"{tool['name']} {where}: {label}"))
            if INVISIBLE.search(text):
                findings.append(PFinding("tool-descriptions", "high", "DESC-POISON", f"{tool['name']} {where}: invisible Unicode characters"))
            if len(text) > MAX_DESCRIPTION:
                findings.append(PFinding("tool-descriptions", "medium", "DESC-LONG", f"{tool['name']} {where}: {len(text)} characters"))
    return findings


def stage_manifest_pin(project: Path, ctx: dict) -> list[PFinding]:
    manifest = json.loads((project / "mcp-manifest.json").read_text(encoding="utf-8"))
    lock = json.loads((project / "mcp-manifest.lock.json").read_text(encoding="utf-8"))
    pinned = lock.get("tools", {})
    current = {t["name"]: description_fingerprint(t) for t in manifest.get("tools", [])}
    findings = []
    for name, fingerprint in current.items():
        if name not in pinned:
            findings.append(PFinding("manifest-pin", "high", "PIN-ADDED", f"new tool '{name}' is not in the approved lock"))
        elif pinned[name] != fingerprint:
            findings.append(PFinding("manifest-pin", "high", "PIN-CHANGED", f"tool '{name}': description or schema differs from the approved lock"))
    for name in pinned:
        if name not in current:
            findings.append(PFinding("manifest-pin", "medium", "PIN-REMOVED", f"tool '{name}' was removed (update the lock)"))
    return findings


STAGES = {
    "sast": stage_sast,
    "secrets": stage_secrets,
    "deps": stage_deps,
    "tool-descriptions": stage_tool_descriptions,
    "manifest-pin": stage_manifest_pin,
}


# ------------------------------------------------------------------ the gate
def apply_policy(results: dict, policy: dict, pr: dict | None) -> tuple[list[PFinding], list[PFinding]]:
    """Return (blocking findings, waived findings)."""
    approvals = policy["approvals"]
    pr = pr or {}
    approvers = set(approvals.get("approvers", []))
    valid = {a for a in pr.get("approved_by", []) if a in approvers and not (approvals.get("forbid_self_approval") and a == pr.get("author"))}
    never_waivable = set(policy.get("never_waivable", []))
    threshold = SEVERITY[policy["block_on_severity"]]
    blocking, waived = [], []
    for result in results.values():
        for finding in result.findings:
            if finding.code in approvals.get("required_for", []) and valid and finding.code not in never_waivable:
                waived.append(finding)
            elif SEVERITY[finding.severity] >= threshold:
                blocking.append(finding)
    return blocking, waived


@dataclass
class PipelineResult:
    stages: dict
    blocking: list
    waived: list
    missing: list
    exit_code: int


def run_pipeline(project, policy_path=DEFAULT_POLICY, pr: dict | None = None, stages: dict | None = None, fail_fast: bool = False) -> PipelineResult:
    project = Path(project)
    policy = load_policy(policy_path)
    if pr is None and (project / "pr.json").exists():
        pr = json.loads((project / "pr.json").read_text(encoding="utf-8"))
    stages = stages if stages is not None else STAGES
    results: dict[str, StageResult] = {}
    for name, fn in stages.items():
        result = StageResult(name)
        try:
            result.findings = fn(project, {})
        except Exception as exc:  # noqa: BLE001 - fail closed: a crashing check is not a passing check
            result.error = f"{type(exc).__name__}: {exc}"
        results[name] = result
        if fail_fast and (result.error or any(SEVERITY[f.severity] >= SEVERITY[policy["block_on_severity"]] for f in result.findings)):
            break
    blocking, waived = apply_policy(results, policy, pr)
    missing = [s for s in policy["required_stages"] if s not in results]
    errored = [r.name for r in results.values() if r.error]
    failed = bool(blocking or missing or errored)
    return PipelineResult(results, blocking, waived, missing, 1 if failed else 0)


def format_report(result: PipelineResult) -> str:
    lines = []
    for name, stage in result.stages.items():
        lines.append(f"stage {name:<18} {stage.status:<9} {len(stage.findings)} finding(s)" + (f"  ERROR {stage.error}" if stage.error else ""))
        for finding in stage.findings:
            lines.append(f"    {finding}")
    for finding in result.waived:
        lines.append(f"waived by approval: {finding}")
    for name in result.missing:
        lines.append(f"missing required stage: {name}")
    lines.append(f"policy-gate: {'BUILD BROKEN' if result.exit_code else 'build may continue'} ({len(result.blocking)} blocking)")
    return "\n".join(lines)


# ------------------------------------------------------------------ workflow lint
SHA_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
REQUIRED_JOBS = ["sast", "secrets", "dependency-audit", "tool-description-scan", "manifest-pin", "policy-gate"]


def lint_workflow(path: str | Path) -> list[str]:
    """Check the workflow file itself (the pipeline is code too)."""
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    problems = []
    triggers = data.get("on", data.get(True, {}))
    trigger_names = set(triggers) if isinstance(triggers, dict) else {triggers} if isinstance(triggers, str) else set(triggers or [])
    if "pull_request_target" in trigger_names:
        problems.append("uses pull_request_target (privileged trigger on untrusted code)")
    perms = data.get("permissions")
    if perms is None:
        problems.append("no top-level permissions block")
    elif isinstance(perms, dict) and any(v == "write" for v in perms.values()):
        problems.append("top-level permissions include write")
    jobs = data.get("jobs", {})
    for required in REQUIRED_JOBS:
        if required not in jobs:
            problems.append(f"missing job: {required}")
    gate = jobs.get("policy-gate", {})
    needs = gate.get("needs", [])
    for required in REQUIRED_JOBS[:-1]:
        if required in jobs and required not in needs:
            problems.append(f"policy-gate does not need: {required}")
    for name, job in jobs.items():
        for step in job.get("steps", []):
            uses = step.get("uses")
            if uses and not SHA_RE.match(uses):
                problems.append(f"{name}: action not pinned to a full commit SHA: {uses}")
            if "${{" in step.get("run", "") and "github.event" in step.get("run", ""):
                problems.append(f"{name}: untrusted github.event data inside a run: step (script injection)")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", required=True)
    parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    parser.add_argument("--pr", help="JSON file with author and approved_by")
    parser.add_argument("--stage", help="run only one stage (what a single CI job does)")
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args(argv)
    pr = json.loads(Path(args.pr).read_text(encoding="utf-8")) if args.pr else None
    stages = {args.stage: STAGES[args.stage]} if args.stage else None
    result = run_pipeline(args.project, args.policy, pr, stages, args.fail_fast)
    if args.stage:
        result.missing = []
        result.exit_code = 1 if result.blocking or any(r.error for r in result.stages.values()) else 0
    print(format_report(result))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
