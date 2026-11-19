"""Git commit signing with SSH keys (gpg.format ssh), plus a pure-Python concept fallback.

Real path: needs `git` >= 2.34 and `ssh-keygen`. An ephemeral key lives in a temp dir and is thrown away.
Fallback: a toy HMAC "signature" over a commit-like payload. It teaches what a signature binds
(content AND identity). Real SSH signatures are asymmetric (Ed25519): the verifier holds only
the public key, so it cannot forge. HMAC is symmetric, so it is only a stand-in for teaching.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import subprocess
from pathlib import Path


def ssh_signing_available() -> bool:
    return shutil.which("git") is not None and shutil.which("ssh-keygen") is not None


# ---------------- real SSH signing ----------------

def _env(home: Path) -> dict[str, str]:
    env = dict(os.environ)
    empty = home / "empty.gitconfig"
    empty.write_text("")
    env.update({"HOME": str(home), "USERPROFILE": str(home), "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": str(empty), "GIT_TERMINAL_PROMPT": "0"})
    return env


def git(repo: Path, home: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(["git", *args], cwd=repo, env=_env(home), capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()}")
    return p


def make_key(directory: Path, name: str) -> Path:
    key = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key)],
                   check=True, capture_output=True)
    return Path(str(key) + ".pub")


def setup_signing_repo(root: Path, email: str, pub: Path) -> Path:
    """Configure a repo exactly as a developer would: ssh format, signing key, sign by default,
    and an allowed_signers file so verification can say 'good'."""
    kind, blob, *_ = pub.read_text().split()
    signers = root / "allowed_signers"
    signers.write_text(f'{email} namespaces="git" {kind} {blob}\n')
    repo = root / "repo"
    repo.mkdir()
    git(repo, root, "init", "-q", "-b", "main")
    for k, v in [("gpg.format", "ssh"), ("user.signingkey", pub.as_posix()), ("commit.gpgsign", "true"),
                 ("gpg.ssh.allowedSignersFile", signers.as_posix()), ("user.name", "Alice Real"), ("user.email", email)]:
        git(repo, root, "config", k, v)
    return repo


def signed_commit(repo: Path, root: Path, filename: str, text: str, message: str) -> None:
    (repo / filename).write_text(text)
    git(repo, root, "add", filename)
    git(repo, root, "commit", "-q", "-m", message)


def verify(repo: Path, root: Path, rev: str = "HEAD") -> tuple[bool, str]:
    p = git(repo, root, "verify-commit", rev, check=False)
    return p.returncode == 0, (p.stderr + p.stdout).strip()


def status_letter(repo: Path, root: Path, rev: str = "HEAD") -> str:
    return git(repo, root, "log", "-1", "--format=%G?", rev).stdout.strip()


def tamper_message(repo: Path, root: Path, new_message: str) -> None:
    """Rewrite HEAD without signing (what an attacker with write access can do)."""
    git(repo, root, "commit", "-q", "--amend", "--no-gpg-sign", "-m", new_message)


# ---------------- pure-Python concept fallback ----------------

def commit_payload(tree: str, parent: str, author: str, message: str) -> bytes:
    return f"tree {tree}\nparent {parent}\nauthor {author}\n\n{message}\n".encode()


def commit_id(payload: bytes) -> str:
    return hashlib.sha1(b"commit %d\0" % len(payload) + payload).hexdigest()  # git-style object id


def toy_sign(payload: bytes, secret: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def toy_verify(payload: bytes, signature: str, secret: bytes) -> bool:
    return hmac.compare_digest(toy_sign(payload, secret), signature)
