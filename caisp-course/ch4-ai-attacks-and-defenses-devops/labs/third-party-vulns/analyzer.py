"""A tiny software composition analysis (SCA) tool for AI projects, offline.

    python analyzer.py requirements.txt              # report
    python analyzer.py my-requirements.txt --fix     # print a fixed requirements file

It does what ``pip-audit`` / OSV-Scanner do, in miniature:
  1. read the pinned dependencies,
  2. add TRANSITIVE dependencies from a dependency map,
  3. match every pinned version against advisory ranges,
  4. propose the smallest version that clears every advisory for that package.

The advisory file is fictional (see advisories.json). Real tools query live databases such
as OSV or the PyPI advisory database. No third-party library is needed here: the version
parser handles plain numeric versions only (real tools use ``packaging``).
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|>|<)?\s*([0-9][0-9A-Za-z.]*)?\s*(?:#.*)?$")


def parse_version(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v))


def in_range(version: str, spec: str) -> bool:
    """spec like '>=1.0.0,<1.4.2' or '<1.5.0'."""
    v = parse_version(version)
    for part in spec.split(","):
        m = re.match(r"\s*(>=|<=|==|>|<)\s*([\d.]+)", part)
        if not m:
            raise ValueError(f"bad range: {spec}")
        op, ref = m.group(1), parse_version(m.group(2))
        ok = {">=": v >= ref, "<=": v <= ref, "==": v == ref, ">": v > ref, "<": v < ref}[op]
        if not ok:
            return False
    return True


@dataclass(frozen=True)
class Requirement:
    name: str
    op: str | None
    version: str | None

    @property
    def pinned(self) -> bool:
        return self.op == "==" and self.version is not None


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> list[Requirement]:
    out = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = REQ_RE.match(line)
        if m:
            out.append(Requirement(normalize(m.group(1)), m.group(2), m.group(3)))
    return out


@dataclass
class Finding:
    package: str
    version: str
    advisory: str
    severity: str
    type: str
    fixed: str
    via: str  # "direct" or the parent package

    def __str__(self) -> str:
        return (f"{self.severity:<9}{self.package}=={self.version}  {self.advisory}  {self.type}  "
                f"-> fix {self.fixed}  ({self.via})")


def load_db(path: Path | None = None) -> dict:
    return json.loads((path or HERE / "advisories.json").read_text(encoding="utf-8"))


def scan(requirements: list[Requirement], db: dict) -> list[Finding]:
    advisories = db["advisories"]
    deps = db.get("dependencies", {})
    top_pins = {r.name: r for r in requirements if r.pinned}  # a top-level pin overrides a '>=' child need
    todo: list[tuple[Requirement, str]] = [(r, "direct") for r in requirements]
    seen: set[tuple[str, str | None]] = set()
    findings: list[Finding] = []
    while todo:
        req, via = todo.pop(0)
        if (req.name, req.version) in seen:
            continue
        seen.add((req.name, req.version))
        if req.version:
            for adv in advisories:
                if normalize(adv["package"]) == req.name and in_range(req.version, adv["affected"]):
                    findings.append(Finding(req.name, req.version, adv["id"], adv["severity"], adv["type"],
                                            adv["fixed"], via))
        for child in deps.get(req.name, []):
            for c in parse_requirements(child):
                todo.append((top_pins.get(c.name, c), req.name))
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.package))


def propose_fixes(findings: list[Finding]) -> dict[str, str]:
    """Per package: the highest 'fixed' version among its findings clears all of them."""
    fixes: dict[str, str] = {}
    for f in findings:
        if f.package not in fixes or parse_version(f.fixed) > parse_version(fixes[f.package]):
            fixes[f.package] = f.fixed
    return fixes


def apply_fixes(text: str, fixes: dict[str, str]) -> str:
    """Rewrite direct pins. A transitive finding needs a pin or constraint line added."""
    direct = {r.name for r in parse_requirements(text)}
    lines = []
    for line in text.splitlines():
        m = REQ_RE.match(line)
        if m and normalize(m.group(1)) in fixes and m.group(2) == "==":
            name = normalize(m.group(1))
            line = f"{m.group(1)}=={fixes[name]}"
        lines.append(line)
    for name, version in fixes.items():
        if name not in direct:
            lines.append(f"{name}=={version}  # constraint added to fix a transitive dependency")
    return "\n".join(lines) + "\n"


def downgrades(old: str, new: str) -> list[str]:
    o = {r.name: r for r in parse_requirements(old)}
    return [n.name for n in parse_requirements(new)
            if n.name in o and o[n.name].version and n.version and parse_version(n.version) < parse_version(o[n.name].version)]


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    path = Path(argv[0])
    text = path.read_text(encoding="utf-8")
    db = load_db()
    findings = scan(parse_requirements(text), db)
    if "--fix" in argv:
        print(apply_fixes(text, propose_fixes(findings)), end="")
        return 0
    for f in findings:
        print(f)
    print(f"\n{len(findings)} finding(s) in {path.name}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
