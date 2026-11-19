"""Four independent ways to catch a postmark-style backdoor in a new package version.

1. review_diff       read the diff between the pinned version and the new one
2. behavior_check    a contract test: the tool must do exactly what its description says
3. EgressGuard       the server only gets a transport that refuses unknown recipients and hosts
4. verify_pin / check_host_config   the host config pins an exact version; the content hash must match

Everything here is simulated. The "mail transport" records messages and sends nothing.
"""

from __future__ import annotations

import difflib
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


def load_package_server(package_dir: str | Path):
    path = Path(package_dir) / "server.py"
    name = f"mailer_pkg_{hashlib.sha1(str(path.resolve()).encode()).hexdigest()[:8]}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------- the fake mail world
@dataclass
class RecordingTransport:
    """Stands in for the SMTP/API client. Records every message; delivers nothing."""

    sent: list = field(default_factory=list)

    def send(self, message: dict) -> None:
        self.sent.append(message)

    def recipients(self) -> list:
        return [r for m in self.sent for key in ("to", "cc", "bcc") for r in m[key]]


class EgressBlocked(Exception):
    pass


class EgressGuard:
    """A transport wrapper owned by the HOST, not by the package: only approved recipient domains get mail."""

    def __init__(self, inner, allowed_domains: set[str]):
        self.inner, self.allowed = inner, {d.lower() for d in allowed_domains}
        self.blocked: list = []

    def send(self, message: dict) -> None:
        for key in ("to", "cc", "bcc"):
            for recipient in message[key]:
                domain = recipient.rsplit("@", 1)[-1].lower()
                if domain not in self.allowed:
                    self.blocked.append(recipient)
                    raise EgressBlocked(f"recipient domain not allowed: {domain}")
        self.inner.send(message)


# ---------------------------------------------------------------- 1. diff review
RISKY_IMPORTS = ("base64", "socket", "http", "urllib", "requests", "subprocess", "ctypes", "os", "smtplib")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
B64 = re.compile(r"""["'][A-Za-z0-9+/]{16,}={0,2}["']""")
URL = re.compile(r"https?://[^\s\"']+")


def review_diff(old_source: str, new_source: str) -> list[tuple[str, str]]:
    """Return (severity, reason) for suspicious ADDED lines. A human still decides."""
    findings = []
    for line in difflib.unified_diff(old_source.splitlines(), new_source.splitlines(), lineterm="", n=0):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        text = line[1:].strip()
        match = re.match(r"(?:import|from)\s+(\w+)", text)
        if match and match.group(1) in RISKY_IMPORTS:
            findings.append(("medium", f"new import of '{match.group(1)}': {text}"))
        if re.search(r"\bbcc\b", text, re.IGNORECASE) and "[]" not in text.split("bcc")[-1][:6]:
            findings.append(("high", f"recipient field 'bcc' now has content: {text[:80]}"))
        if EMAIL.search(text):
            findings.append(("high", f"new e-mail address in code: {EMAIL.search(text).group(0)}"))
        if B64.search(text):
            findings.append(("high", f"base64-looking string literal (hidden value?): {text[:70]}"))
        if URL.search(text):
            findings.append(("high", f"new URL in code: {URL.search(text).group(0)}"))
        if re.search(r"\b(exec|eval)\(", text):
            findings.append(("high", f"dynamic code execution: {text[:70]}"))
    return findings


# ---------------------------------------------------------------- 2. behavior (contract) test
def behavior_check(module) -> list[str]:
    """The description says 'send an email to one recipient'. Anything else is a violation."""
    transport = RecordingTransport()
    request = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "send_email", "arguments": {"to": "bob@customer.example", "subject": "hi", "body": "BODY-CANARY"}},
    }
    module.handle(request, transport)
    problems = []
    if len(transport.sent) != 1:
        problems.append(f"expected 1 message, got {len(transport.sent)}")
    if transport.recipients() != ["bob@customer.example"]:
        problems.append(f"recipients are {transport.recipients()}, expected only the requested one")
    return problems


# ---------------------------------------------------------------- 4. pinning
def tree_hash(package_dir: str | Path) -> str:
    digest = hashlib.sha256()
    root = Path(package_dir)
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        digest.update(str(path.relative_to(root)).replace("\\", "/").encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def make_lock(package_dir: str | Path) -> dict:
    meta = json.loads((Path(package_dir) / "metadata.json").read_text(encoding="utf-8"))
    return {meta["name"]: {"version": meta["version"], "tree_sha256": tree_hash(package_dir)}}


def verify_pin(package_dir: str | Path, lock: dict) -> list[str]:
    meta = json.loads((Path(package_dir) / "metadata.json").read_text(encoding="utf-8"))
    entry = lock.get(meta["name"])
    if entry is None:
        return [f"{meta['name']} is not in the lock file"]
    problems = []
    if entry["version"] != meta["version"]:
        problems.append(f"version {meta['version']} is not the pinned {entry['version']}")
    if entry["tree_sha256"] != tree_hash(package_dir):
        problems.append("package content hash differs from the lock file")
    return problems


NPM_PINNED = re.compile(r"^(@?[\w./-]+)@\d+\.\d+\.\d+$")
PY_PINNED = re.compile(r"^[\w.-]+==\d+(\.\d+)*$")


def check_host_config(config: dict) -> list[str]:
    """Flag servers launched with npx/uvx/pipx that do not pin an exact version."""
    problems = []
    for name, server in config.get("mcpServers", {}).items():
        command, args = server.get("command", ""), server.get("args", [])
        if command not in {"npx", "uvx", "pipx"}:
            continue
        spec = next((a for a in args if not a.startswith("-")), "")
        if command == "npx" and not NPM_PINNED.match(spec):
            problems.append(f"{name}: '{spec}' is not pinned to an exact version")
        if command in {"uvx", "pipx"} and not PY_PINNED.match(spec):
            problems.append(f"{name}: '{spec}' is not pinned with ==")
        if "-y" in args:
            problems.append(f"{name}: '-y' auto-confirms installs (no human sees what is installed)")
    return problems
