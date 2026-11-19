"""OWASP Dependency-Check style analysis of a pom.xml, offline (a demo-level twin).

Real Dependency-Check collects EVIDENCE (vendor, product, version) from jar manifests, pom files and
file names, guesses CPE names from it, and matches them against NVD CPE data. That matching by NAME is
why it finds things OSV-style coordinate matching cannot, and also why it produces false positives.
This twin does the same with pom coordinates:
  mode="cpe"        guess CPE vendor/product from groupId/artifactId, give a confidence level
  mode="coordinate" exact groupId:artifactId match (how OSV, GHSA and OSS Index work)
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from aisec_lab import load_lab_module

osv = load_lab_module(str(Path(__file__).resolve().parents[1] / "_shared" / "x.py"), "osv_common")

NOISE_VENDOR_TOKENS = {"com", "org", "net", "io", "dev", "co"}
CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "HIGHEST": 4}


@dataclass
class Dep:
    group: str
    artifact: str
    version: str | None
    scope: str = "compile"

    @property
    def coord(self) -> str:
        return f"{self.group}:{self.artifact}"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(el: ET.Element, name: str) -> str | None:
    for c in el:
        if _local(c.tag) == name:
            return (c.text or "").strip()
    return None


def parse_pom(path: Path) -> tuple[list[Dep], list[str]]:
    root = ET.parse(path).getroot()
    props = {}
    for el in root:
        if _local(el.tag) == "properties":
            props = {_local(p.tag): (p.text or "").strip() for p in el}
    props["project.version"] = _child_text(root, "version") or ""
    warns: list[str] = []

    def subst(v: str | None, who: str) -> str | None:
        if v is None:
            return None
        def rep(m):
            if m.group(1) in props:
                return props[m.group(1)]
            warns.append(f"unresolved property ${{{m.group(1)}}} for {who}")
            return m.group(0)
        out = re.sub(r"\$\{([^}]+)\}", rep, v)
        return None if "${" in out else out

    def deps_of(container: ET.Element) -> list[Dep]:
        out = []
        for d in container.iter():
            if _local(d.tag) != "dependency":
                continue
            g, a = _child_text(d, "groupId"), _child_text(d, "artifactId")
            out.append(Dep(g or "", a or "", subst(_child_text(d, "version"), f"{g}:{a}"),
                           _child_text(d, "scope") or "compile"))
        return out

    managed, direct = {}, []
    for el in root:
        if _local(el.tag) == "dependencyManagement":
            managed = {d.coord: d.version for d in deps_of(el)}
        elif _local(el.tag) == "dependencies":
            direct = deps_of(el)
    for d in direct:
        if d.version is None and d.coord in managed:
            d.version = managed[d.coord]
    for d in direct:
        if d.version is None:
            warns.append(f"{d.coord}: version unknown, cannot be analysed")
    return direct, warns


# ------------------------------------------------------------------ CPE guessing

def cpe_candidates(dep: Dep) -> list[tuple[str, str, bool]]:
    """(vendor, product, exact) guesses. 'exact' means the product equals the whole artifactId."""
    vendors = [t for t in re.split(r"[.\-]", dep.group) if t and t not in NOISE_VENDOR_TOKENS]
    parts = dep.artifact.split("-")
    products = [("-".join(parts[:i]), i == len(parts)) for i in range(len(parts), 0, -1)]
    return [(v, p, ex) for v in vendors for p, ex in products] + [("", p, ex) for p, ex in products]


def parse_cpe(cpe: str) -> tuple[str, str]:
    f = cpe.split(":")
    return f[3], f[4]


def scan(deps: list[Dep], db: list[dict], mode: str = "cpe", skip_test_scope: bool = True) -> list:
    out, seen = [], set()
    for dep in deps:
        if dep.version is None or (skip_test_scope and dep.scope == "test"):
            continue
        if mode == "coordinate":
            for rec, aff in osv.match_package(db, "Maven", dep.coord, dep.version):
                f = osv.make_finding(rec, aff, "Maven", dep.coord, dep.version, source="coordinate")
                f.note = "exact groupId:artifactId match"
                out.append(f)
            continue
        cands = cpe_candidates(dep)
        for rec in db:
            cpe = rec.get("database_specific", {}).get("cpe")
            aff = next((a for a in rec.get("affected", []) if a.get("package", {}).get("ecosystem") == "Maven"), None)
            if not cpe or aff is None:
                continue
            vendor, product = parse_cpe(cpe)
            hit = [(v, p, ex) for v, p, ex in cands if p == product and (v == vendor or v == "")]
            if not hit or not osv.in_ranges(dep.version, aff.get("ranges", [])):
                continue
            vendor_ok = any(v == vendor for v, _, _ in hit)
            exact = any(ex for _, _, ex in hit)
            conf = ("HIGHEST" if exact else "MEDIUM") if vendor_ok else ("MEDIUM" if exact else "LOW")
            key = (dep.coord, rec["id"])
            if key in seen:
                continue
            seen.add(key)
            f = osv.make_finding(rec, aff, "Maven", dep.coord, dep.version, source="cpe")
            f.note = f"matched CPE {cpe.split(':*')[0]} with {conf} confidence (scope {dep.scope})"
            out.append(f)
    return osv.sort_findings(out)


def confidence_of(f) -> str:
    m = re.search(r"with (\w+) confidence", f.note)
    return m.group(1) if m else "HIGHEST"


def break_build(findings: list, fail_cvss: float = 7.0, min_confidence: str = "MEDIUM") -> int:
    """Dependency-Check style: fail when any finding scores >= fail_cvss (failBuildOnCVSS). Findings below
    the confidence floor are reported but do not break the build."""
    floor = CONFIDENCE_RANK[min_confidence]
    counted = [f for f in findings if CONFIDENCE_RANK[confidence_of(f)] >= floor]
    return 1 if any(f.cvss >= fail_cvss for f in counted) else 0
