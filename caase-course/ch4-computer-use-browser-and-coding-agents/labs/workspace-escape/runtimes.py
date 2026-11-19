"""Two simulated agent runtimes and a set of workspace-escape attacks.

``StandardRuntime``  : the common application-level check: join the path, test a
                       string prefix. Looks safe; is not.
``IsolatedRuntime``  : a chroot-like virtual root: every path (absolute ones too) is
                       re-rooted, canonicalised with symlinks resolved, then checked
                       against the real root. A small policy adds deny rules.

Only temp directories are used. The "secret" is a FAKE canary file.
"""

from __future__ import annotations

import fnmatch
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

CANARY = "FAKE-OUTSIDE-SECRET-CANARY-5521"


class Denied(Exception):
    pass


# ------------------------------------------------------------------- the layout


class Layout:
    """root/work (workspace), root/outside/secret.txt, root/work-evil/secret.txt (prefix sibling)."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.work = self.root / "work"
        self.outside = self.root / "outside"
        self.evil = self.root / "work-evil"
        for d in (self.work, self.outside, self.evil, self.work / "sub"):
            d.mkdir(parents=True)
        (self.work / "ok.txt").write_text("normal project file")
        (self.work / "sub" / "deep.txt").write_text("deep project file")
        (self.outside / "secret.txt").write_text(CANARY)
        (self.evil / "secret.txt").write_text(CANARY)
        (self.work / ".env").write_text("FAKE_KEY=not-a-real-key")
        self.symlink_ok = self._make_symlink()

    def _make_symlink(self) -> bool:
        try:
            os.symlink(self.outside, self.work / "shortcut", target_is_directory=True)
            return True
        except (OSError, NotImplementedError):
            return False

    def close(self):
        self._tmp.cleanup()


# ------------------------------------------------------------------- mini shell


def _shell(runtime, cmdline: str) -> str:
    """Supports only `cd DIR` and `cat FILE`, joined by &&."""
    out = ""
    for part in cmdline.split("&&"):
        part = part.strip()
        if part.startswith("cd "):
            runtime.chdir(part[3:].strip())
        elif part.startswith("cat "):
            out += runtime.read(part[4:].strip())
        else:
            raise Denied(f"command not supported: {part}")
    return out


# --------------------------------------------------------------------- standard


class StandardRuntime:
    name = "standard"

    def __init__(self, workspace: Path):
        self.ws = str(workspace)
        self.cwd = str(workspace)

    def _resolve(self, p: str) -> str:
        joined = os.path.join(self.cwd, p)          # absolute p replaces cwd (os.path.join rule)
        if not joined.startswith(self.ws):          # string prefix check, no normalisation
            raise Denied("outside workspace")
        return joined

    def read(self, p: str) -> str:
        try:
            return Path(self._resolve(p)).read_text()
        except FileNotFoundError:
            return ""

    def chdir(self, p: str) -> None:
        self.cwd = self._resolve(p)                  # same flawed check

    def shell(self, cmdline: str) -> str:
        return _shell(self, cmdline)


# --------------------------------------------------------------------- isolated


@dataclass
class Policy:
    deny_globs: tuple[str, ...] = (".env", "*.pem", "id_*")
    max_bytes: int = 100_000


class IsolatedRuntime:
    name = "isolated"

    def __init__(self, workspace: Path, policy: Policy | None = None):
        self.root = Path(workspace).resolve()
        self.cwd = self.root
        self.policy = policy or Policy()
        self.audit: list[str] = []

    def _canon(self, p: str) -> Path:
        raw = Path(p)
        if raw.is_absolute() or raw.root or raw.drive:                         # chroot idea: "/" means the workspace root
            rel = Path(*raw.parts[1:]) if len(raw.parts) > 1 else Path()
            base = self.root / rel
        else:
            base = self.cwd / raw
        real = Path(os.path.realpath(base))            # resolves .. and symlinks
        if real != self.root and self.root not in real.parents:
            self.audit.append(f"DENY escape: {p!r} -> {real}")
            raise Denied("path resolves outside the workspace root")
        return real

    def read(self, p: str) -> str:
        real = self._canon(p)
        if any(fnmatch.fnmatch(real.name, g) for g in self.policy.deny_globs):
            self.audit.append(f"DENY policy: {real.name}")
            raise Denied("blocked by policy")
        if not real.is_file():
            return ""
        if real.stat().st_size > self.policy.max_bytes:
            raise Denied("file too large")
        return real.read_text()

    def chdir(self, p: str) -> None:
        self.cwd = self._canon(p)

    def shell(self, cmdline: str) -> str:
        return _shell(self, cmdline)


# ---------------------------------------------------------------------- attacks


def attacks(layout: Layout) -> dict:
    """name -> function(runtime) returning the text the attacker obtained."""
    secret_abs = str(layout.outside / "secret.txt")
    return {
        "dotdot": lambda r: r.read("../outside/secret.txt"),
        "nested-dotdot": lambda r: r.read("./sub/../../outside/secret.txt"),
        "absolute-path": lambda r: r.read(secret_abs),
        "prefix-sibling": lambda r: r.read("../work-evil/secret.txt"),
        "absolute-prefix-sibling": lambda r: r.read(str(layout.evil / "secret.txt")),
        "symlink": lambda r: r.read("shortcut/secret.txt"),
        "shell-cd-dotdot": lambda r: r.shell("cd .. && cd outside && cat secret.txt"),
        "shell-absolute-cat": lambda r: r.shell(f"cat {secret_abs}"),
    }


def run_attacks(layout: Layout, runtime) -> dict[str, str]:
    """Return name -> 'ESCAPED' | 'blocked' | 'skipped'."""
    results = {}
    for name, fn in attacks(layout).items():
        if name == "symlink" and not layout.symlink_ok:
            results[name] = "skipped"
            continue
        runtime.cwd = type(runtime.cwd)(layout.work) if not isinstance(runtime.cwd, str) else str(layout.work)
        try:
            text = fn(runtime)
        except Denied:
            results[name] = "blocked"
            continue
        results[name] = "ESCAPED" if CANARY in text else "blocked"
    return results


def count(results: dict[str, str]) -> tuple[int, int]:
    """(escapes, blocked)"""
    return (sum(v == "ESCAPED" for v in results.values()), sum(v == "blocked" for v in results.values()))
