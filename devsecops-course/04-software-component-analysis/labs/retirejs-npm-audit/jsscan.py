"""RetireJS-style and npm-audit-style scanners, offline twins.

retire_scan : recognise JS libraries from file names and banners, then look them up.
npm_audit   : walk package-lock.json (v2/v3 `packages` map), resolve the dependency graph the way
              Node does, report direct and transitive findings with the path and whether a fix is
              inside the declared semver range.
Both read the same OSV-format advisory database (../_shared/advisories.osv.json).
"""
from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path

from aisec_lab import load_lab_module

osv = load_lab_module(str(Path(__file__).resolve().parents[1] / "_shared" / "x.py"), "osv_common")

VERSION_RE = r"([0-9]+(?:\.[0-9]+)+)"


# ------------------------------------------------------------------ npm audit style

def load_lock(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))["packages"]


def resolve(packages: dict, frm: str, dep: str) -> str | None:
    """Node resolution: look in frm/node_modules/dep, then climb parent node_modules folders."""
    base = frm
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in packages:
            return cand
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def _edges(packages: dict, loc: str, include_dev: bool):
    meta = packages[loc]
    deps = dict(meta.get("dependencies", {}))
    if loc == "" and include_dev:
        deps.update(meta.get("devDependencies", {}))
    for name, rng in deps.items():
        target = resolve(packages, loc, name)
        if target:
            yield name, rng, target


def npm_audit(packages: dict, db: list[dict], omit_dev: bool = False) -> list:
    """BFS from the root so every package gets the SHORTEST path (what `npm audit` prints as 'via')."""
    paths: dict[str, list[str]] = {"": []}
    declared: dict[str, str] = {}
    queue = deque([""])
    while queue:
        loc = queue.popleft()
        for name, rng, target in _edges(packages, loc, include_dev=not omit_dev):
            if target not in paths:
                paths[target] = paths[loc] + [name]
                declared[target] = rng
                queue.append(target)
    root_dev = set(packages[""].get("devDependencies", {}))
    out = []
    for loc, path in paths.items():
        if loc == "":
            continue
        name, version = path[-1], packages[loc]["version"]
        for rec, aff in osv.match_package(db, "npm", name, version):
            f = osv.make_finding(rec, aff, "npm", name, version, direct=len(path) == 1,
                                 dev=packages[loc].get("dev", False) or path[0] in root_dev,
                                 path=["(root)"] + path, source="npm-audit")
            brk = osv.fix_is_breaking(declared[loc], f.fixed)
            f.note = ("no fix available" if brk is None else
                      "fix needs a MAJOR upgrade (breaking)" if brk else "fix is inside your declared range")
            out.append(f)
    return osv.sort_findings(out)


# ------------------------------------------------------------------ RetireJS style

def load_extractors(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern.replace("§§version§§", VERSION_RE))


def identify(path: Path, extractors: dict, max_bytes: int = 8192) -> list[tuple[str, str, str]]:
    """Return (library, version, how) for one file. Filename first, then content banner."""
    found, text = {}, None
    for lib, spec in extractors.items():
        for pat in spec.get("filename", []):
            m = _compile(pat).search(path.name)
            if m:
                found.setdefault((lib, m.group(1)), "filename")
        if text is None:
            text = path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
        for pat in spec.get("filecontent", []):
            m = _compile(pat).search(text)
            if m:
                found[(lib, m.group(1))] = "filecontent" if (lib, m.group(1)) not in found else "filename+filecontent"
    return [(lib, ver, how) for (lib, ver), how in found.items()]


def retire_scan(webroot: Path, extractors: dict, db: list[dict]) -> list:
    out = []
    for p in sorted(Path(webroot).rglob("*.js")):
        for lib, ver, how in identify(p, extractors):
            npm_name = extractors[lib].get("npm", lib)
            hits = osv.match_package(db, "npm", npm_name, ver)
            for rec, aff in hits:
                f = osv.make_finding(rec, aff, "npm", npm_name, ver, source="retire")
                f.path = [p.relative_to(webroot).as_posix()]
                f.note = f"found by {how}"
                out.append(f)
    return osv.sort_findings(out)


def compare(retire: list, audit: list) -> dict[str, set]:
    r = {(f.package, f.advisory) for f in retire}
    a = {(f.package, f.advisory) for f in audit}
    return {"both": r & a, "retire_only": r - a, "audit_only": a - r}
