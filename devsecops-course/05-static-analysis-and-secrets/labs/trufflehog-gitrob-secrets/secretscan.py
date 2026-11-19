"""Secrets scanner in the style of TruffleHog / gitleaks (content rules + entropy) and gitrob (file names),
with a git HISTORY scan. Offline, standard library only. All secrets are FAKE and built at runtime.

Ideas shown:
  * rules: provider-style regex, generic `password = "..."`, private key header, entropy;
  * verification: our fake internal token carries a checksum, so a bad one is LOW confidence (TruffleHog
    verifies a candidate against the real provider; checksums and prefixes are the offline cousin);
  * history: a secret deleted in a later commit is still in the repository;
  * CI mode: scan only a commit range, and fail the build on high-confidence findings.
gitrob is unmaintained; the file-name signatures here are the part of its idea worth keeping.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import subprocess
import zlib
from dataclasses import dataclass
from pathlib import Path

# ------------------------------------------------------------------ fake secrets, built from pieces

PREFIX = "ac" + "me_" + "live_"          # an INTERNAL token format that real scanners do not know


def _body(seed: str, n: int = 20) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    digest = hashlib.sha256(seed.encode()).digest()
    return "".join(alphabet[b % len(alphabet)] for b in digest[:n])


def checksum(body: str) -> str:
    return f"{zlib.crc32(body.encode()) & 0xFFFF:04x}"


def make_fake_token(seed: str, valid: bool = True) -> str:
    body = _body(seed)
    cs = checksum(body)
    if not valid:
        cs = f"{(int(cs, 16) ^ 0xFFFF):04x}"
    return PREFIX + body + cs


def make_fake_private_key(seed: str) -> str:
    head = "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----"
    foot = "-----END " + "OPENSSH PRIVATE" + " KEY-----"
    return "\n".join([head, _body(seed, 20) + _body(seed + "2", 20), foot, ""])


# ------------------------------------------------------------------ rules

ACME_TOKEN = re.compile(r"\bacme_live_([A-Za-z0-9]{20})([0-9a-f]{4})\b")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")
GENERIC = re.compile(r"""(?i)\b(?:password|passwd|secret|api_?key|token)\b\s*[:=]\s*["']([^"'\s]{8,})["']""")
HIGH_ENTROPY = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
PLACEHOLDER = re.compile(r"(?i)^(changeme|example|your[_-]|xxx+|<.*>|\$\{.*\}|\*+|todo|dummy|placeholder)")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
ALLOW_PRAGMA = "pragma: allowlist secret"

FILE_SIGNATURES = [   # gitrob idea: the NAME of a file is already a finding
    (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), "SSH private key file"),
    (re.compile(r"\.(pem|p12|pfx|jks|kdbx)$"), "key or keystore file"),
    (re.compile(r"(^|/)\.env(\.(?!example|sample|template).+)?$"), "dotenv file with real values"),
    (re.compile(r"(^|/)(credentials|\.htpasswd|\.netrc)$"), "credentials file"),
]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return max(0.0, -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values()))


def redact(s: str) -> str:
    return f"{s[:4]}...({len(s)} chars)"


def secret_id(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


@dataclass
class Finding:
    rule: str
    path: str
    line: int
    preview: str
    sid: str
    confidence: str            # HIGH | MEDIUM | LOW
    note: str = ""
    commit: str = ""
    subject: str = ""
    entropy: float = 0.0


def scan_text(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW_PRAGMA in line:
            continue
        covered: list[tuple[int, int]] = []
        for m in ACME_TOKEN.finditer(line):
            ok = checksum(m.group(1)) == m.group(2)
            out.append(Finding("acme-token", path, n, redact(m.group(0)), secret_id(m.group(0)),
                               "HIGH" if ok else "LOW",
                               "checksum valid: treat as live" if ok else "checksum FAILS: probably test data",
                               entropy=round(entropy(m.group(0)), 2)))
            covered.append(m.span())
        if PRIVATE_KEY.search(line):
            out.append(Finding("private-key-block", path, n, "-----BEGIN ... PRIVATE KEY-----", secret_id(line), "HIGH"))
        for m in GENERIC.finditer(line):
            val = m.group(1)
            if PLACEHOLDER.match(val) or entropy(val) < 3.0 or any(a <= m.start(1) < b for a, b in covered):
                continue
            out.append(Finding("generic-assignment", path, n, redact(val), secret_id(val), "MEDIUM",
                               entropy=round(entropy(val), 2)))
            covered.append(m.span())
        for m in HIGH_ENTROPY.finditer(line):
            tok = m.group(0)
            if any(a <= m.start() < b for a, b in covered) or UUID.match(tok) or PLACEHOLDER.match(tok):
                continue
            if re.fullmatch(r"[0-9a-f]{32,64}", tok) and re.search(r"(?i)sha|hash|commit|digest|checksum", line):
                continue                      # a git or file hash, not a secret
            if entropy(tok) >= 4.2:
                out.append(Finding("high-entropy-string", path, n, redact(tok), secret_id(tok), "LOW",
                                   "random-looking string; confirm by hand", entropy=round(entropy(tok), 2)))
    return out


def scan_filename(path: str) -> Finding | None:
    for pat, why in FILE_SIGNATURES:
        if pat.search(path):
            return Finding("sensitive-filename", path, 0, why, secret_id(path), "MEDIUM", "gitrob-style name signature")
    return None


def scan_tree(root: Path) -> list[Finding]:
    root, out = Path(root), []
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".git" not in p.relative_to(root).parts:
            rel = p.relative_to(root).as_posix()
            f = scan_filename(rel)
            if f:
                out.append(f)
            try:
                out += scan_text(p.read_text(encoding="utf-8"), rel)
            except UnicodeDecodeError:
                continue
    return out


# ------------------------------------------------------------------ git history

def git_available() -> bool:
    return shutil.which("git") is not None


def git_env(home: Path) -> dict:
    """Isolated git: no system or global config, fixed dates so commit ids are reproducible."""
    empty = Path(home) / "empty.gitconfig"
    empty.write_text("")
    env = dict(os.environ)
    env.update({"HOME": str(home), "USERPROFILE": str(home), "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": str(empty), "GIT_TERMINAL_PROMPT": "0",
                "GIT_AUTHOR_DATE": "2026-01-01T12:00:00+0000", "GIT_COMMITTER_DATE": "2026-01-01T12:00:00+0000"})
    return env


def git(repo: Path, home: Path, *args: str) -> str:
    base = ["git", "-c", "user.name=Lab User", "-c", "user.email=lab@example.invalid", "-c", "commit.gpgsign=false",
            "-c", "core.autocrlf=false", "-c", "init.defaultBranch=main"]
    p = subprocess.run(base + list(args), cwd=repo, env=git_env(home), capture_output=True, text=True, encoding="utf-8")
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()}")
    return p.stdout


def scan_history(repo: Path, home: Path, rev_range: str | None = None) -> list[Finding]:
    """Scan every ADDED line of every commit on every ref (or just `rev_range`, as a CI job would)."""
    args = ["log", "--reverse", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=@@COMMIT %H|%s"]
    args += [rev_range] if rev_range else ["--all"]
    raw = git(repo, home, *args)
    out, commit, subject, path, lineno = [], "", "", "", 0
    for line in raw.splitlines():
        if line.startswith("@@COMMIT "):
            commit, subject = line[9:].split("|", 1)
        elif line.startswith("+++ b/"):
            path = line[6:]
            f = scan_filename(path)
            if f:
                f.commit, f.subject = commit[:8], subject
                out.append(f)
        elif line.startswith("@@ "):
            m = re.search(r"\+(\d+)", line)
            lineno = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            for f in scan_text(line[1:], path):
                f.line, f.commit, f.subject = lineno, commit[:8], subject
                out.append(f)
            lineno += 1
    return out


def classify_history(history: list[Finding], head: list[Finding]) -> list[Finding]:
    """First sighting of each distinct secret, marked still-present or not-in-HEAD-but-in-history."""
    live = {f.sid for f in head}
    seen, out = set(), []
    for f in history:
        if f.sid in seen:
            continue
        seen.add(f.sid)
        f.note = (f.note + "; " if f.note else "") + ("STILL IN HEAD" if f.sid in live else "NOT in HEAD but STILL IN HISTORY (deleted later, or only on another branch): rotate it")
        out.append(f)
    return out


def ci_gate(findings: list[Finding], fail_on: str = "MEDIUM") -> int:
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    return 1 if any(rank[f.confidence] >= rank[fail_on] for f in findings) else 0


# ------------------------------------------------------------------ demo repository

def build_demo_repo(root: Path, home: Path) -> None:
    def write(rel: str, text: str):
        p = Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    token, side_token = make_fake_token("main-token"), make_fake_token("side-branch-token")
    git(root, home, "init")
    write("app.py", "def main():\n    return 'hello'\n")
    write("config.py", f'API_TOKEN = "{token}"\nTIMEOUT = 5\n')
    write("deploy/id_rsa", make_fake_private_key("deploy"))
    git(root, home, "add", "-A")
    git(root, home, "commit", "-m", "initial import")
    git(root, home, "branch", "old-feature")
    write("config.py", 'import os\nAPI_TOKEN = os.environ["API_TOKEN"]\nTIMEOUT = 5\n')
    git(root, home, "rm", "-q", "deploy/id_rsa")
    git(root, home, "add", "-A")
    git(root, home, "commit", "-m", "move token to environment, drop key file")
    write("README.md", 'Setup: set password = "changeme" in your local .env.example\n'
                       "Build id 123e4567-e89b-12d3-a456-426614174000\n"
                       "commit sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n")
    write("tests/test_client.py", f'TOKEN = "{make_fake_token("fixture", valid=False)}"  # test data\n')
    git(root, home, "add", "-A")
    git(root, home, "commit", "-m", "docs and tests")
    git(root, home, "checkout", "-q", "old-feature")
    write("notes.txt", f"scratch: {side_token}\n")
    git(root, home, "add", "-A")
    git(root, home, "commit", "-m", "wip notes (never merged)")
    git(root, home, "checkout", "-q", "main")
