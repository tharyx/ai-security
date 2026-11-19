"""Mock coding agent that reads a repo README and git commit messages.

Everything is simulated:
  * "shell" commands are NEVER executed; they are appended to ``World.shell_log``.
    A command that pipes a download into a shell sets ``World.remote_exec = True``
    (the simulated damage).
  * The "secret" is a FAKE canary file inside a temp "home" directory.
"""

from __future__ import annotations

import re
import shlex
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CANARY = "FAKE-SSH-KEY-CANARY-7731"

# --------------------------------------------------------------------- the world


class World:
    """A throwaway home directory with a canary 'private key'."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        (self.home / ".ssh").mkdir()
        (self.home / ".ssh" / "id_fake").write_text(CANARY)
        self.shell_log: list[str] = []
        self.files_read: list[str] = []
        self.remote_exec = False
        self.leaked: list[str] = []

    def close(self):
        self._tmp.cleanup()


# ----------------------------------------------------------------- gullible model

DIRECTIVE_RE = re.compile(r"AGENT\s*:\s*(?:before you do anything else,\s*)?run\s*:\s*(.+?)(?:-->|$)", re.IGNORECASE | re.MULTILINE)
READ_RE = re.compile(r"(?:AI assistants|AGENT)\s*:?.*?read\s*:\s*(\S+)", re.IGNORECASE)


def gullible_planner(context: list[tuple[str, str]]) -> list[dict]:
    """Returns actions. It obeys instruction-like text from ANY source (that is the bug)."""
    actions: list[dict] = []
    for source, text in context:
        for m in DIRECTIVE_RE.finditer(text):
            actions.append({"tool": "shell", "cmd": m.group(1).strip(), "from": source})
        for m in READ_RE.finditer(text):
            actions.append({"tool": "read", "path": m.group(1).strip(), "from": source})
    # the legitimate task: run the tests
    actions.append({"tool": "shell", "cmd": "pytest", "from": "user"})
    return actions


# ---------------------------------------------------------------------- defenses

HIDDEN_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
INJECTION_HINT_RE = re.compile(r"(AGENT\s*:|AI assistants|ignore (all )?previous|curl\s+[^|]*\|\s*(sh|bash))", re.IGNORECASE)


def sanitize_repo_text(text: str) -> tuple[str, list[str]]:
    """Strip hidden comments, drop instruction-like lines, and report what was removed."""
    removed: list[str] = []

    def _strip(m):
        removed.append(m.group(0))
        return ""

    text = HIDDEN_COMMENT_RE.sub(_strip, text)
    kept = []
    for line in text.splitlines():
        if INJECTION_HINT_RE.search(line):
            removed.append(line)
        else:
            kept.append(line)
    return "\n".join(kept), removed


DEFAULT_ALLOWED = ("pytest", "pip install -e .", "git status", "git diff", "ls")
PIPE_TO_SHELL_RE = re.compile(r"\|\s*(sh|bash|zsh|python)\b")


@dataclass
class Defenses:
    sanitize: bool = False
    allowlist: tuple[str, ...] | None = None       # exact-prefix command allowlist
    deny_sensitive_paths: bool = False
    approve: object = None                          # callable(action) -> bool ; None = no approval gate
    taint_needs_approval: bool = False              # after reading untrusted text, side effects need approval
    log: list[str] = field(default_factory=list)


SENSITIVE = (".ssh", ".aws", ".gnupg", ".env", "id_rsa", "id_ed25519", "id_fake")


def _allowed(cmd: str, allow: tuple[str, ...]) -> bool:
    if PIPE_TO_SHELL_RE.search(cmd) or any(c in cmd for c in (";", "&&", "||", "`", "$(")):
        return False
    try:
        shlex.split(cmd)
    except ValueError:
        return False
    return any(cmd == a or cmd.startswith(a + " ") for a in allow)


def execute(action: dict, world: World, d: Defenses, tainted: bool) -> dict:
    """Deterministic policy layer between the model and the world."""
    if action["tool"] == "shell":
        cmd = action["cmd"]
        if d.allowlist is not None and not _allowed(cmd, d.allowlist):
            # not on the allowlist: ask a human if there is a gate, else block
            if d.approve is None or not d.approve(action):
                d.log.append(f"BLOCK shell {cmd!r}")
                return {"status": "blocked", "reason": "command not on allowlist"}
        elif d.taint_needs_approval and tainted and action["from"] != "user":
            if d.approve is None or not d.approve(action):
                d.log.append(f"BLOCK (tainted origin {action['from']}) {cmd!r}")
                return {"status": "blocked", "reason": "instruction came from untrusted repo content"}
        world.shell_log.append(cmd)  # simulated: never really runs
        if PIPE_TO_SHELL_RE.search(cmd) and "curl" in cmd:
            world.remote_exec = True
        return {"status": "executed"}
    if action["tool"] == "read":
        p = Path(action["path"].replace("~", str(world.home))).expanduser()
        if d.deny_sensitive_paths and any(s in str(p) for s in SENSITIVE):
            d.log.append(f"BLOCK read {action['path']}")
            return {"status": "blocked", "reason": "sensitive path"}
        if p.is_file():
            content = p.read_text()
            world.files_read.append(str(p))
            if CANARY in content:
                world.leaked.append(content)
            return {"status": "executed"}
        return {"status": "error", "reason": "no such file"}
    return {"status": "error", "reason": "unknown tool"}


def run_agent(world: World, defenses: Defenses, task: str = "Set up the project and run the tests") -> list[dict]:
    readme = (FIXTURES / "repo" / "README.md").read_text()
    commits = (FIXTURES / "commits.txt").read_text()
    context = [("user", task), ("README.md", readme), ("git log", commits)]
    tainted = True  # we read repo text
    if defenses.sanitize:
        cleaned = []
        for source, text in context:
            if source == "user":
                cleaned.append((source, text))
            else:
                text, removed = sanitize_repo_text(text)
                for r in removed:
                    defenses.log.append(f"STRIP {source}: {r.strip()[:60]}")
                cleaned.append((source, text))
        context = cleaned
    results = []
    for action in gullible_planner(context):
        results.append({"action": action, **execute(action, world, defenses, tainted)})
    return results
