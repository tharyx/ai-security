"""Simulate the pre-commit stage: read the config, pick hooks for the staged files, run the scanners,
and BLOCK the commit (exit 1) if a hook reports findings. Also shows the CI backstop for `--no-verify`.

Nothing is installed in git here; see the pre-commit-hooks lab for a real `.git/hooks/pre-commit`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

# `entry` names used in the fixture config -> built-in scanner functions (loaded lazily by the caller)
ENTRY_TO_SCANNER = {"csse-sca-check": "sca_check", "csse-sast-check": "sast_check"}


@dataclass
class HookOutcome:
    hook_id: str
    status: str  # Passed | Failed | Skipped
    messages: list[str]


def run_stage(config_text: str, staged: dict[str, str], scanners) -> tuple[int, list[HookOutcome]]:
    cfg = yaml.safe_load(config_text)
    outcomes: list[HookOutcome] = []
    for repo in cfg["repos"]:
        for hook in repo["hooks"]:
            pat = re.compile(hook.get("files", ".*"))
            matched = {p: t for p, t in staged.items() if pat.search(p)}
            if not matched and not hook.get("always_run"):
                outcomes.append(HookOutcome(hook["id"], "Skipped", []))
                continue
            fn_name = ENTRY_TO_SCANNER.get(hook["entry"])
            if fn_name is None:
                outcomes.append(HookOutcome(hook["id"], "Failed", [f"unknown entry {hook['entry']!r}: refusing to run"]))
                continue
            msgs = getattr(scanners, fn_name)(matched)
            outcomes.append(HookOutcome(hook["id"], "Failed" if msgs else "Passed", msgs))
    code = 1 if any(o.status == "Failed" for o in outcomes) else 0
    return code, outcomes


def commit(staged: dict[str, str], config_text: str, scanners, no_verify: bool = False) -> tuple[bool, list[HookOutcome]]:
    """Return (commit_created, outcomes). `no_verify` models `git commit --no-verify`."""
    if no_verify:
        return True, []
    code, outcomes = run_stage(config_text, staged, scanners)
    return code == 0, outcomes


def ci_recheck(tree: dict[str, str], config_text: str, scanners) -> int:
    """Same hooks on the whole tree in CI (like `pre-commit run --all-files`). The server-side backstop."""
    return run_stage(config_text, tree, scanners)[0]


def load_tree(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)).replace("\\", "/"): p.read_text() for p in root.rglob("*") if p.is_file()}
