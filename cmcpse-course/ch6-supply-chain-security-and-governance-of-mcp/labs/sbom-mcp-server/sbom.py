"""Generate and analyze a CycloneDX-style SBOM for an MCP server project (offline).

Input: a lock file (`lock.json`, a simplified stand-in for uv.lock / package-lock.json).
Output: a CycloneDX 1.5 shaped JSON document: metadata, components with purl/hashes/licenses,
and a dependency graph. It follows the CycloneDX structure but is NOT validated against the official
schema in this lab; use cyclonedx-py / cdxgen / Syft for real SBOMs and the CycloneDX schema to validate.

MCP angle: the server itself is the top component, and we add *custom properties* (transport and tool
names) so a reviewer can see what the SBOM describes. These property names are lab conventions, not part
of any MCP or CycloneDX standard (verify current guidance for AI/agent BOMs).
"""

from __future__ import annotations

import json
import uuid
from collections import defaultdict, deque
from pathlib import Path

NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")


def purl(name: str, version: str | None) -> str:
    return f"pkg:pypi/{name}" + (f"@{version}" if version else "")


def generate_sbom(project_dir: str | Path, timestamp: str = "2026-01-01T00:00:00Z") -> dict:
    lock = json.loads((Path(project_dir) / "lock.json").read_text(encoding="utf-8"))
    project = lock["project"]
    root_ref = f"{project['name']}@{project['version']}"
    components, dependencies, direct_refs = [], [], []
    ref_by_name = {}
    for pkg in lock["packages"]:
        ref_by_name[pkg["name"]] = purl(pkg["name"], pkg.get("version"))
    for pkg in lock["packages"]:
        ref = ref_by_name[pkg["name"]]
        comp = {
            "type": "library",
            "bom-ref": ref,
            "name": pkg["name"],
            "purl": ref,
            "licenses": [{"license": {"id": pkg["license"]}}] if pkg.get("license") != "UNKNOWN" else [],
            "properties": [
                {"name": "lab:direct", "value": str(bool(pkg.get("direct"))).lower()},
                {"name": "lab:registry", "value": pkg.get("registry", "")},
            ],
        }
        if pkg.get("version"):
            comp["version"] = pkg["version"]
        else:
            comp["properties"].append({"name": "lab:constraint", "value": pkg.get("constraint", "")})
        if pkg.get("hash"):
            comp["hashes"] = [{"alg": "SHA-256", "content": pkg["hash"].split(":", 1)[1]}]
        components.append(comp)
        if pkg.get("direct"):
            direct_refs.append(ref)
        dependencies.append({"ref": ref, "dependsOn": [ref_by_name[r] for r in pkg.get("requires", [])]})
    dependencies.insert(0, {"ref": root_ref, "dependsOn": direct_refs})
    serial = uuid.uuid5(NAMESPACE, json.dumps(lock, sort_keys=True))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "cmcpse-lab-sbom", "version": "0.1"}]},
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": project["name"],
                "version": project["version"],
                "licenses": [{"license": {"id": project["license"]}}],
                "properties": [{"name": "lab:mcp:transport", "value": project["transport"]}]
                + [{"name": "lab:mcp:tool", "value": t} for t in project["tools"]],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }


def validate_sbom(sbom: dict) -> list[str]:
    """Structural sanity checks (not the full CycloneDX schema)."""
    problems = []
    if sbom.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be CycloneDX")
    if not str(sbom.get("specVersion", "")).startswith("1."):
        problems.append("unexpected specVersion")
    refs = [c["bom-ref"] for c in sbom.get("components", [])]
    root = sbom["metadata"]["component"]["bom-ref"]
    if len(refs) != len(set(refs)):
        problems.append("duplicate bom-ref values")
    known = set(refs) | {root}
    for dep in sbom.get("dependencies", []):
        for ref in [dep["ref"]] + dep["dependsOn"]:
            if ref not in known:
                problems.append(f"dependency refers to unknown component {ref}")
    return problems


def _prop(component: dict, name: str) -> str:
    return next((p["value"] for p in component.get("properties", []) if p["name"] == name), "")


def _version_tuple(version: str) -> tuple:
    return tuple(int(x) for x in version.split(".") if x.isdigit())


def _depths(sbom: dict) -> dict:
    graph = {d["ref"]: d["dependsOn"] for d in sbom["dependencies"]}
    root = sbom["metadata"]["component"]["bom-ref"]
    depth, queue = {root: 0}, deque([root])
    while queue:
        cur = queue.popleft()
        for nxt in graph.get(cur, []):
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                queue.append(nxt)
    return depth


def analyze_sbom(sbom: dict, advisories: list[dict], policy: dict) -> dict:
    """Score every component and summarize. Higher score = more review needed."""
    depth = _depths(sbom)
    rows, totals = [], defaultdict(int)
    for comp in sbom["components"]:
        reasons, score = [], 0
        version = comp.get("version")
        if not version:
            reasons.append(f"unpinned (constraint {_prop(comp, 'lab:constraint')})")
            score += 3
        elif not comp.get("hashes"):
            reasons.append("no hash")
            score += 1
        for adv in advisories:
            if version and adv["package"] == comp["name"] and _version_tuple(version) < _version_tuple(adv["fixed"]):
                reasons.append(f"{adv['id']} ({adv['severity']}): {adv['summary']}")
                score += {"critical": 8, "high": 5, "medium": 3, "low": 1}[adv["severity"]]
        lic = comp["licenses"][0]["license"]["id"] if comp.get("licenses") else None
        if lic is None:
            reasons.append("license unknown")
            score += 1
        elif lic in policy["denied_licenses"]:
            reasons.append(f"denied license {lic}")
            score += 2
        if _prop(comp, "lab:registry") not in policy["allowed_registries"]:
            reasons.append(f"registry not allowed: {_prop(comp, 'lab:registry')}")
            score += 3
        level = depth.get(comp["bom-ref"], 99)
        if level >= 2:
            totals["transitive"] += 1
        if level >= 3:
            reasons.append(f"deep transitive dependency (depth {level})")
            score += 1
        rows.append({"name": comp["name"], "version": version, "depth": level, "score": score, "reasons": reasons})
        totals["components"] += 1
    rows.sort(key=lambda r: (-r["score"], r["name"]))
    worst = rows[0]["score"] if rows else 0
    return {
        "components": totals["components"],
        "direct": sum(1 for c in sbom["components"] if _prop(c, "lab:direct") == "true"),
        "transitive": totals["components"] - sum(1 for c in sbom["components"] if _prop(c, "lab:direct") == "true"),
        "max_depth": max(depth.values()),
        "vulnerable": [r["name"] for r in rows if any(x.startswith("LAB-ADV") for x in r["reasons"])],
        "unpinned": [r["name"] for r in rows if any(x.startswith("unpinned") for x in r["reasons"])],
        "denied_licenses": [r["name"] for r in rows if any(x.startswith("denied license") for x in r["reasons"])],
        "unknown_licenses": [r["name"] for r in rows if "license unknown" in r["reasons"]],
        "bad_registry": [r["name"] for r in rows if any(x.startswith("registry not allowed") for x in r["reasons"])],
        "rows": rows,
        "worst_score": worst,
        "acceptable": worst <= policy["max_acceptable_score"],
    }


def render_report(report: dict) -> str:
    lines = [
        f"components: {report['components']} (direct {report['direct']}, transitive {report['transitive']}, max depth {report['max_depth']})",
        f"vulnerable: {report['vulnerable']}",
        f"unpinned: {report['unpinned']}",
        f"denied licenses: {report['denied_licenses']}  unknown licenses: {report['unknown_licenses']}",
        f"registry not allowed: {report['bad_registry']}",
        "risk ranking:",
    ]
    for row in report["rows"]:
        if row["score"]:
            lines.append(f"  {row['score']:>2}  {row['name']}=={row['version'] or '?'}: " + "; ".join(row["reasons"]))
    lines.append(f"verdict: {'acceptable' if report['acceptable'] else 'NEEDS REVIEW'} (worst score {report['worst_score']})")
    return "\n".join(lines)
