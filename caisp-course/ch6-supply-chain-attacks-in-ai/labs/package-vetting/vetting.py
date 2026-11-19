"""Automated package vetting: score a package's metadata BEFORE you install it.

No network. The metadata comes from a fixture (a stand-in for the PyPI JSON API plus
download statistics). The score is a simple, explainable sum of risk signals:

    age            new packages are riskier (attackers register fresh names)
    maintainers    one maintainer = one stolen account away from compromise
    downloads      near-zero downloads = nobody has looked at it
    typosquat      the name is 1-2 edits away from a popular package
    hallucinated   the name is on a list of names that LLMs invent (slopsquatting)
    install script the package runs code at install time (setup.py / build hooks)
    repo url       no link to source code to review

Verdicts: allow (<30), review (30-59), block (>=60). A human owns the final decision.
This is a teaching scorer: the weights are arbitrary and should be tuned on your data.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
WEIGHTS = {
    "hallucinated_new": 50, "hallucinated_old": 15,
    "typosquat_1": 40, "typosquat_2": 30, "separator_trick": 40, "combosquat": 25,
    "age_lt_30": 20, "age_lt_180": 10,
    "single_maintainer": 5,
    "downloads_lt_100": 15, "downloads_lt_1000": 5,
    "install_script": 20, "no_repo": 10,
}
BLOCK_AT, REVIEW_AT = 60, 30
COMBO_PREFIXES = ("python-", "py-")
COMBO_SUFFIXES = ("-py", "-official", "-secure", "-pro", "-lite", "-helper")


def normalize(name: str) -> str:
    """PEP 503 style: case-insensitive, runs of - _ . are the same."""
    out, prev_sep = [], False
    for ch in name.lower():
        if ch in "-_.":
            if not prev_sep:
                out.append("-")
            prev_sep = True
        else:
            out.append(ch)
            prev_sep = False
    return "".join(out)


def levenshtein(a: str, b: str) -> int:
    """Edit distance: insertions, deletions and substitutions each cost 1."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def transposed(a: str, b: str) -> bool:
    """True when b is a with two neighbouring letters swapped (reqeusts vs requests)."""
    if len(a) != len(b) or a == b:
        return False
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]


def typosquat_target(name: str, popular: list[str]) -> tuple[str, str] | None:
    """Return (popular name, kind) when `name` imitates a popular package."""
    n = normalize(name)
    pops = {normalize(p): p for p in popular}
    if n in pops:
        return None  # it IS the popular package (same normalized name)
    for pn, original in pops.items():
        if n.replace("-", "") == pn.replace("-", ""):
            return original, "separator_trick"
        if transposed(n, pn):
            return original, "typosquat_1"
    best: tuple[int, str] | None = None
    for pn, original in pops.items():
        if min(len(n), len(pn)) < 5:
            continue  # short names: edit distance would flag too many innocents
        d = levenshtein(n, pn)
        if d <= 2 and (best is None or d < best[0]):
            best = (d, original)
    if best:
        return best[1], f"typosquat_{best[0]}"
    for pn, original in pops.items():
        if n in {pre + pn for pre in COMBO_PREFIXES} | {pn + suf for suf in COMBO_SUFFIXES}:
            return original, "combosquat"
    return None


@dataclass
class Verdict:
    name: str
    score: int
    decision: str
    reasons: list[str] = field(default_factory=list)


def score_package(meta: dict, popular: list[str], hallucinated: list[str]) -> Verdict:
    name = meta["name"]
    pts: list[tuple[int, str]] = []
    age = meta["age_days"]
    hallu = {normalize(h) for h in hallucinated}
    if normalize(name) in hallu:
        if age < 180:
            pts.append((WEIGHTS["hallucinated_new"], "name is on the list of names LLMs invent AND the package is new (slopsquatting)"))
        else:
            pts.append((WEIGHTS["hallucinated_old"], "name is on the list of names LLMs invent (old package, check who owns it)"))
    hit = typosquat_target(name, popular)
    if hit:
        pts.append((WEIGHTS[hit[1]], f"name imitates '{hit[0]}' ({hit[1]})"))
    if age < 30:
        pts.append((WEIGHTS["age_lt_30"], f"first released {age} days ago"))
    elif age < 180:
        pts.append((WEIGHTS["age_lt_180"], f"first released {age} days ago"))
    if meta["maintainers"] <= 1:
        pts.append((WEIGHTS["single_maintainer"], "single maintainer"))
    dl = meta["weekly_downloads"]
    if dl < 100:
        pts.append((WEIGHTS["downloads_lt_100"], f"only {dl} downloads a week"))
    elif dl < 1000:
        pts.append((WEIGHTS["downloads_lt_1000"], f"only {dl} downloads a week"))
    if meta["has_install_script"]:
        pts.append((WEIGHTS["install_script"], "runs code at install time"))
    if not meta["has_repo_url"]:
        pts.append((WEIGHTS["no_repo"], "no source repository link"))
    score = min(100, sum(p for p, _ in pts))
    decision = "block" if score >= BLOCK_AT else "review" if score >= REVIEW_AT else "allow"
    return Verdict(name, score, decision, [r for _, r in pts])


def internal_names_on_public(internal_names: list[str], fixture: dict) -> list[str]:
    """Dependency-confusion canary: which of OUR private names also exist on the public index?"""
    public = {normalize(p["name"]) for p in fixture["registry"]}
    return [n for n in internal_names if normalize(n) in public]


def load_fixture(path: str | Path = HERE / "fixtures" / "packages.json") -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def vet_requested(names: list[str], fixture: dict) -> list[Verdict]:
    """Vet names an AI assistant suggested. Names missing from the registry do not exist."""
    registry = {normalize(p["name"]): p for p in fixture["registry"]}
    out = []
    for n in names:
        meta = registry.get(normalize(n))
        if meta is None:
            out.append(Verdict(n, 100, "block", [
                "not in the registry: the model invented it. Do NOT register this name yourself "
                "and do NOT install anything that appears under it later without vetting"]))
            continue
        out.append(score_package(meta, fixture["popular_names"], fixture["hallucinated_names"]))
    return out


def main(argv: list[str]) -> int:
    fx = load_fixture()
    names = argv or [p["name"] for p in fx["registry"]]
    results = vet_requested(names, fx)
    for v in results:
        print(f"{v.decision.upper():7} {v.score:3}  {v.name}")
        for r in v.reasons:
            print(f"                 - {r}")
    return 1 if any(v.decision == "block" for v in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
