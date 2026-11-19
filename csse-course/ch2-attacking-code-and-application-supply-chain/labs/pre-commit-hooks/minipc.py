"""A tiny working clone of the `pre-commit` idea, to learn how hooks gate a commit.

It reads a `.pre-commit-config.yaml`-style file and runs BUILT-IN checks only (no downloads, no
arbitrary `entry` commands). It can also install itself as a real `.git/hooks/pre-commit` in a
local repo, so `git commit` is really blocked when a check fails.

This is a teaching model of the real tool (https://pre-commit.com). The real one clones hook
repositories at a pinned `rev` and runs their code: see the exploiting-pre-commit-hooks lab for why
that needs trust. Verify real behaviour in the pre-commit docs.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

PRIVATE_KEY_MARKERS = ("-----BEGIN " + "RSA PRIVATE KEY-----", "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
                       "-----BEGIN " + "PRIVATE KEY-----")


def trailing_whitespace(path: str, data: bytes) -> list[str]:
    out = []
    for i, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        if line != line.rstrip():
            out.append(f"{path}:{i}: trailing whitespace")
    return out


def end_of_file_fixer(path: str, data: bytes) -> list[str]:
    return [f"{path}: file does not end with a single newline"] if data and not data.endswith(b"\n") else []


def detect_private_key(path: str, data: bytes) -> list[str]:
    text = data.decode("utf-8", "replace")
    return [f"{path}: looks like it contains a private key"] if any(m in text for m in PRIVATE_KEY_MARKERS) else []


def check_added_large_files(path: str, data: bytes, max_kb: int = 500) -> list[str]:
    return [f"{path}: {len(data) // 1024} KB is larger than {max_kb} KB"] if len(data) > max_kb * 1024 else []


def check_merge_conflict(path: str, data: bytes) -> list[str]:
    if re.search(rb"^(<<<<<<< |=======$|>>>>>>> )", data, re.M):
        return [f"{path}: merge conflict markers"]
    return []


def check_yaml(path: str, data: bytes) -> list[str]:
    if not path.endswith((".yml", ".yaml")):
        return []
    try:
        list(yaml.safe_load_all(data))
    except yaml.YAMLError as e:
        return [f"{path}: invalid YAML ({type(e).__name__})"]
    return []


BUILTIN = {
    "trailing-whitespace": trailing_whitespace,
    "end-of-file-fixer": end_of_file_fixer,
    "detect-private-key": detect_private_key,
    "check-added-large-files": check_added_large_files,
    "check-merge-conflict": check_merge_conflict,
    "check-yaml": check_yaml,
}


@dataclass
class HookResult:
    hook_id: str
    passed: bool
    messages: list[str]


def load_config(text: str) -> dict:
    cfg = yaml.safe_load(text) or {}
    if "repos" not in cfg:
        raise ValueError("config has no 'repos'")
    return cfg


def run_hooks(config: dict, files: dict[str, bytes]) -> list[HookResult]:
    results: list[HookResult] = []
    for repo in config["repos"]:
        for hook in repo.get("hooks", []):
            hid = hook["id"]
            func = BUILTIN.get(hid)
            if func is None:
                results.append(HookResult(hid, False, ["unknown hook id (this mini runner only has built-ins)"]))
                continue
            pattern = re.compile(hook["files"]) if hook.get("files") else None
            msgs: list[str] = []
            for path, data in files.items():
                if pattern and not pattern.search(path):
                    continue
                msgs.extend(func(path, data))
            results.append(HookResult(hid, not msgs, msgs))
    return results


def exit_code(results: list[HookResult]) -> int:
    return 0 if all(r.passed for r in results) else 1


# ---- real git integration ----

def staged_files(repo: Path) -> dict[str, bytes]:
    names = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"], cwd=repo,
                           capture_output=True, text=True, check=True).stdout.split()
    files = {}
    for n in names:
        files[n] = subprocess.run(["git", "show", f":{n}"], cwd=repo, capture_output=True, check=True).stdout
    return files


def install_git_hook(repo: Path) -> Path:
    """Write .git/hooks/pre-commit that runs this module against the staged files."""
    hook = repo / ".git" / "hooks" / "pre-commit"
    py = Path(sys.executable).as_posix()
    me = Path(__file__).resolve().as_posix()
    hook.write_text(f'#!/bin/sh\nexec "{py}" "{me}" --git\n', newline="\n")
    hook.chmod(0o755)
    return hook


def main(argv: list[str]) -> int:
    repo = Path.cwd()
    cfg = load_config((repo / ".pre-commit-config.yaml").read_text())
    results = run_hooks(cfg, staged_files(repo))
    for r in results:
        print(f"{r.hook_id:28} {'Passed' if r.passed else 'Failed'}")
        for m in r.messages:
            print(f"  - {m}")
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
