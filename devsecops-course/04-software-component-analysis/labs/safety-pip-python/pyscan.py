"""Safety / pip-audit style scan of a requirements.txt against an OSV-format database (offline twin).

Steps: parse requirements (pins, ranges, extras, markers, hashes, -r includes) -> match advisories ->
add a heuristic reachability check using ast -> apply a break-build gate.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from aisec_lab import load_lab_module

osv = load_lab_module(str(Path(__file__).resolve().parents[1] / "_shared" / "x.py"), "osv_common")

IMPORT_NAMES = {"pdfmake-py": "pdfmake"}     # distribution name -> import name when they differ


@dataclass
class Req:
    name: str
    version: str          # pinned version, or the lowest allowed one for a range
    pinned: bool
    source: str           # file:line
    spec: str = ""


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()          # PEP 503


LINE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?P<spec>(?:[<>=!~]=?[^;\s#]+(?:\s*,\s*[<>=!~]=?[^;\s#]+)*)?)")


def parse_requirements(path: Path, _seen: set | None = None) -> tuple[list[Req], list[str]]:
    path, _seen = Path(path), _seen or set()
    reqs, warns = [], []
    if path.resolve() in _seen:
        return reqs, [f"{path.name}: include loop ignored"]
    _seen.add(path.resolve())
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split(" #")[0].split("\t#")[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            inc = path.parent / line.split(None, 1)[1].strip()
            if inc.exists():
                r2, w2 = parse_requirements(inc, _seen)
                reqs += r2
                warns += w2
            else:
                warns.append(f"{path.name}:{n}: include {inc.name} not found")
            continue
        if line.startswith("-"):
            continue
        m = LINE.match(line)
        if not m:
            warns.append(f"{path.name}:{n}: cannot parse '{line}'")
            continue
        spec = m["spec"].strip()
        pin = re.match(r"^==\s*([0-9][^\s,;]*)$", spec)
        if pin:
            reqs.append(Req(normalize(m["name"]), pin.group(1), True, f"{path.name}:{n}", spec))
            continue
        low = re.search(r"(?:>=|~=|>)\s*([0-9][^\s,;]*)", spec)
        if low:
            reqs.append(Req(normalize(m["name"]), low.group(1), False, f"{path.name}:{n}", spec))
            warns.append(f"{path.name}:{n}: {m['name']} is not pinned ({spec}); assuming lowest allowed {low.group(1)}")
        else:
            warns.append(f"{path.name}:{n}: {m['name']} has no usable version, skipped")
    return reqs, warns


def scan(reqs: list[Req], db: list[dict]) -> list:
    out, seen = [], set()
    for r in reqs:
        for rec, aff in osv.match_package(db, "PyPI", r.name, r.version):
            if (r.name, r.version, rec["id"]) in seen:
                continue                      # the same pin in two files is one finding
            seen.add((r.name, r.version, rec["id"]))
            f = osv.make_finding(rec, aff, "PyPI", r.name, r.version, source="safety")
            f.path = [r.source]
            if not r.pinned:
                f.note = "version not pinned, matched against the lowest allowed version"
            out.append(f)
    return osv.sort_findings(out)


# ------------------------------------------------------------------ reachability (heuristic)

def called_functions(src_dir: Path) -> set[str]:
    """Dotted names of everything called in the code, with import aliases resolved."""
    called: set[str] = set()
    for p in Path(src_dir).rglob("*.py"):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        alias: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    alias[a.asname or a.name.split(".")[0]] = a.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    alias[a.asname or a.name] = f"{node.module}.{a.name}"
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                parts, cur = [], node.func
                while isinstance(cur, ast.Attribute):
                    parts.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    parts.append(alias.get(cur.id, cur.id))
                    called.add(".".join(reversed(parts)))
    return called


def imported_modules(src_dir: Path) -> set[str]:
    mods: set[str] = set()
    for p in Path(src_dir).rglob("*.py"):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module.split(".")[0])
    return mods


def reachability(findings: list, db: list[dict], src_dir: Path):
    """Split findings into (reachable_or_unknown, not_reachable). Not reachable means: the package is
    imported nowhere, or the advisory names vulnerable functions and none of them is ever called."""
    funcs = called_functions(src_dir)
    mods = imported_modules(src_dir)
    recs = {r["id"]: r for r in db}
    keep, drop = [], []
    for f in findings:
        mod = IMPORT_NAMES.get(f.package, f.package.replace("-", "_"))
        vulnerable = recs[f.advisory].get("database_specific", {}).get("affected_functions", [])
        if mod not in mods:
            f.note = (f.note + "; " if f.note else "") + "NOT reachable: package is never imported (maybe transitive or dev-only)"
            drop.append(f)
        elif vulnerable and not any(v in funcs for v in vulnerable):
            f.note = (f.note + "; " if f.note else "") + f"NOT reachable: {', '.join(vulnerable)} is never called"
            drop.append(f)
        else:
            f.note = (f.note + "; " if f.note else "") + ("REACHABLE: " + ", ".join(vulnerable) + " is called" if vulnerable
                                                        else "reachability unknown (no function data)")
            keep.append(f)
    return keep, drop
