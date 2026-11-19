"""Vet a marketplace skill package BEFORE installing it (a course sketch; nothing is executed).

Checks: install scripts, obfuscation, network endpoints, credential paths,
typosquatted names, publisher age, hash and signature.

Real deployments use asymmetric signatures (for example Sigstore/cosign or minisign).
This lab uses an HMAC with a FAKE shared key only so it can run offline in a few lines.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

REFERENCE_DATE = date(2026, 11, 19)           # fixed, so tests are deterministic
MIN_PUBLISHER_AGE_DAYS = 30
TRUSTED_KEYS = {"acme-tools": b"FAKE-PUBLISHER-KEY-acme"}
KNOWN_SKILLS = ["github-helper", "notes-helper", "crypto-tracker", "calendar-sync", "pdf-reader", "web-search"]
ALLOWED_HOSTS = {"api.github.com", "pypi.org"}

INSTALL_NAMES = {"setup.sh", "install.sh", "postinstall.sh", "setup.py", "install.ps1", "setup.ps1", "install.bat"}
CRED_RE = re.compile(r"(\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.aws\b|\.gnupg|Keychains?|wallet\.dat|Login Data|\.npmrc|\.env\b|Cookies)", re.IGNORECASE)
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)", re.IGNORECASE)
B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
OBFUSC_CALL_RE = re.compile(r"(\beval\s*\(|\bexec\s*\(|base64\s+-d|b64decode|fromCharCode|\\x[0-9a-f]{2}\\x[0-9a-f]{2})", re.IGNORECASE)
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class Finding:
    check: str
    severity: str
    detail: str


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def file_hashes(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and p.name != "manifest.json"}


def sign(manifest: dict, key: bytes) -> str:
    payload = json.dumps({k: manifest[k] for k in ("name", "version", "publisher", "files")}, sort_keys=True).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def check_names(manifest: dict) -> list[Finding]:
    name = manifest.get("name", "")
    out = []
    for known in KNOWN_SKILLS:
        d = edit_distance(name, known)
        if 0 < d <= 2:
            out.append(Finding("typosquat", "high", f"name {name!r} is {d} edit(s) from known skill {known!r}"))
    return out


def check_publisher(manifest: dict) -> list[Finding]:
    pub = manifest.get("publisher", {})
    try:
        age = (REFERENCE_DATE - date.fromisoformat(pub.get("created", ""))).days
    except ValueError:
        return [Finding("publisher-age", "medium", "publisher creation date missing or invalid")]
    if age < MIN_PUBLISHER_AGE_DAYS:
        return [Finding("publisher-age", "medium", f"publisher account is only {age} days old")]
    return []


def check_integrity(root: Path, manifest: dict) -> list[Finding]:
    out = []
    declared, actual = manifest.get("files", {}), file_hashes(root)
    if not declared:
        out.append(Finding("hash", "high", "manifest declares no file hashes"))
    for path, h in actual.items():
        if path in declared and declared[path] != h:
            out.append(Finding("hash", "critical", f"{path} does not match the declared sha256"))
        elif path not in declared and declared:
            out.append(Finding("hash", "high", f"{path} is not listed in the manifest"))
    sig = manifest.get("signature")
    key = TRUSTED_KEYS.get(manifest.get("publisher", {}).get("id", ""))
    if not sig:
        out.append(Finding("signature", "high", "package is unsigned"))
    elif key is None:
        out.append(Finding("signature", "high", "publisher key is not trusted"))
    elif not hmac.compare_digest(sig, sign(manifest, key)):
        out.append(Finding("signature", "critical", "signature does not verify"))
    return out


def check_content(root: Path, manifest: dict) -> list[Finding]:
    out = []
    declared_install = manifest.get("install")
    if declared_install:
        out.append(Finding("install-script", "medium", f"manifest declares an install step: {declared_install}"))
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name == "manifest.json":
            continue
        rel = p.relative_to(root).as_posix()
        text = p.read_text(errors="replace")
        if p.name.lower() in INSTALL_NAMES:
            out.append(Finding("install-script", "medium", f"{rel} looks like an install/setup script"))
        if B64_RE.search(text) or OBFUSC_CALL_RE.search(text):
            out.append(Finding("obfuscation", "high", f"{rel}: encoded blob or dynamic execution"))
        for host in sorted(set(URL_RE.findall(text))):
            if host.lower() not in ALLOWED_HOSTS:
                out.append(Finding("endpoint", "high", f"{rel}: network endpoint {host}"))
        m = CRED_RE.search(text)
        if m and p.suffix in (".sh", ".py", ".js", ".ps1", ".bat"):
            out.append(Finding("credential-path", "critical", f"{rel}: references {m.group(0)!r}"))
    return out


def vet(root: Path) -> dict:
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text())
    findings = (check_names(manifest) + check_publisher(manifest)
                + check_integrity(root, manifest) + check_content(root, manifest))
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=-1)
    highs = sum(f.severity in ("high", "critical") for f in findings)
    if worst >= 3 or highs >= 2:
        verdict = "BLOCK"
    elif findings:
        verdict = "REVIEW"
    else:
        verdict = "ALLOW"
    return {"name": manifest.get("name"), "verdict": verdict, "findings": findings}
