"""Name-similarity detector for typosquatting, combosquatting and brandjacking.

Input: a requirements text and a list of popular package names. Output: findings.
Standard library only. Heuristics, not proof: always combine with maintainer, age and download data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Characters that look alike. "rn" looks like "m", "vv" like "w", digits like letters.
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"}
MULTI = {"rn": "m", "vv": "w", "cl": "d"}
COMBO_AFFIXES = (
    "official", "secure", "security", "utils", "util", "tools", "lib", "dev", "core", "client",
    "sdk", "api", "cli", "python", "py", "js", "node", "new", "latest", "fix", "free", "pro",
)
BRANDS = ("aws", "azure", "google", "github", "gitlab", "microsoft", "openai", "anthropic", "docker")


def normalize(name: str) -> str:
    """PyPI treats - _ . as the same and ignores case; do the same before comparing."""
    return re.sub(r"[-_.]+", "-", name.lower())


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def deconfuse(name: str) -> str:
    out = normalize(name)
    for k, v in MULTI.items():
        out = out.replace(k, v)
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in out)


@dataclass
class Finding:
    package: str
    kind: str
    target: str
    detail: str


def check_name(name: str, popular: list[str]) -> list[Finding]:
    n = normalize(name)
    pops = [normalize(p) for p in popular]
    if n in pops:
        return []  # exactly a known package
    out: list[Finding] = []
    for p in pops:
        # 1. homoglyph / look-alike: equal after de-confusing, but not equal before
        if deconfuse(n) == deconfuse(p) and n != p:
            out.append(Finding(name, "homoglyph", p, "looks like the popular name when look-alike characters are mapped"))
            continue
        # 2. typosquat: small edit distance (scaled to length so short names do not match everything)
        if len(p) >= 5:
            d = levenshtein(n, p)
            if 1 <= d <= (1 if len(p) < 8 else 2):
                out.append(Finding(name, "typosquat", p, f"{d} edit(s) away from {p}"))
                continue
        # 3. transposition (adjacent swap), counts as 2 edits in plain Levenshtein
        if len(n) == len(p) and len(p) >= 5:
            diff = [i for i in range(len(p)) if n[i] != p[i]]
            if len(diff) == 2 and diff[1] == diff[0] + 1 and n[diff[0]] == p[diff[1]] and n[diff[1]] == p[diff[0]]:
                out.append(Finding(name, "typosquat", p, "two adjacent letters swapped"))
                continue
        # 4. combosquat: popular name plus a trusted-sounding prefix or suffix
        for aff in COMBO_AFFIXES:
            if n in (f"{p}-{aff}", f"{aff}-{p}", f"{p}{aff}", f"{aff}{p}"):
                out.append(Finding(name, "combosquat", p, f"{p} combined with '{aff}'"))
                break
    # 5. brandjacking: a vendor brand inside a name that is not a known package
    for brand in BRANDS:
        if brand in n and n not in pops and not any(f.kind == "combosquat" for f in out):
            out.append(Finding(name, "brandjack", brand, f"contains the brand '{brand}' but is not a known official package"))
            break
    return out


def parse_requirements(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"[A-Za-z0-9_.\-]+", line)
        if m:
            names.append(m.group(0))
    return names


def scan_requirements(text: str, popular: list[str]) -> list[Finding]:
    found: list[Finding] = []
    for name in parse_requirements(text):
        found.extend(check_name(name, popular))
    return found
