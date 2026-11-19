"""Git commit spoofing in a REAL local repository (temp dir, `git` CLI, nothing pushed anywhere).

Point of the lab: git author and committer names are free text. Anyone can write
`Alice <alice@example.com>`. Only a signature proves who made a commit.

Needs `git` (skip if missing). The signature half also needs `ssh-keygen` (git's SSH signing).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


def git_available() -> bool:
    return shutil.which("git") is not None


def ssh_signing_available() -> bool:
    return git_available() and shutil.which("ssh-keygen") is not None


def _env(home: Path) -> dict[str, str]:
    env = dict(os.environ)
    empty = home / "empty.gitconfig"
    empty.write_text("")
    env.update({
        "HOME": str(home), "USERPROFILE": str(home),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(empty),
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def git(repo: Path, home: Path, *args: str, check: bool = True) -> str:
    p = subprocess.run(["git", *args], cwd=repo, env=_env(home), capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def make_ssh_key(directory: Path, name: str) -> Path:
    """Ephemeral, passphrase-less ed25519 key for the lab. Returns the .pub path."""
    key = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)],
                   check=True, capture_output=True)
    return Path(str(key) + ".pub")


def allowed_signers_line(email: str, pub: Path) -> str:
    kind, blob, *_ = pub.read_text().split()
    return f'{email} namespaces="git" {kind} {blob}\n'


@dataclass
class CommitInfo:
    subject: str
    author: str
    email: str
    sig_status: str  # git %G? : G good, B bad, U valid but signer untrusted, N none, E cannot check


def init_repo(root: Path, signers: Path | None) -> Path:
    repo = root / "repo"
    repo.mkdir()
    git(repo, root, "init", "-q", "-b", "main")
    git(repo, root, "config", "gpg.format", "ssh")
    if signers is not None:
        git(repo, root, "config", "gpg.ssh.allowedSignersFile", signers.as_posix())
    return repo


def commit(repo: Path, home: Path, filename: str, text: str, message: str, name: str, email: str,
           sign_with: Path | None = None) -> None:
    (repo / filename).write_text(text)
    git(repo, home, "add", filename)
    args = ["-c", f"user.name={name}", "-c", f"user.email={email}"]
    if sign_with is not None:
        args += ["-c", f"user.signingkey={sign_with.as_posix()}", "commit", "-q", "-S", "-m", message]
    else:
        args += ["commit", "-q", "--no-gpg-sign", "-m", message]
    git(repo, home, *args)


def read_log(repo: Path, home: Path) -> list[CommitInfo]:
    out = git(repo, home, "log", "--reverse", "--format=%s|%an|%ae|%G?")
    rows = []
    for line in out.strip().splitlines():
        s, a, e, g = line.split("|")
        rows.append(CommitInfo(s, a, e, g))
    return rows


def run_scenario(root: Path) -> list[CommitInfo]:
    """Alice (key trusted) makes a signed commit. Mallory then writes a commit that CLAIMS to be Alice:
    once unsigned, once signed with Mallory's own key. Only the first is trusted."""
    alice_pub = make_ssh_key(root, "alice_key") if ssh_signing_available() else None
    mallory_pub = make_ssh_key(root, "mallory_key") if ssh_signing_available() else None
    signers = None
    if alice_pub:
        signers = root / "allowed_signers"
        signers.write_text(allowed_signers_line("alice@example.com", alice_pub))
    repo = init_repo(root, signers)
    commit(repo, root, "app.txt", "v1\n", "legit change by Alice", "Alice Real", "alice@example.com", alice_pub)
    commit(repo, root, "app.txt", "v2 backdoor\n", "spoofed, unsigned", "Alice Real", "alice@example.com")
    if mallory_pub:
        commit(repo, root, "app.txt", "v3 backdoor\n", "spoofed, signed by wrong key", "Alice Real", "alice@example.com", mallory_pub)
    return read_log(repo, root)


def trusted(info: CommitInfo) -> bool:
    return info.sig_status == "G"


def make_workdir() -> tempfile.TemporaryDirectory:
    return tempfile.TemporaryDirectory(prefix="csse2-spoof-")
