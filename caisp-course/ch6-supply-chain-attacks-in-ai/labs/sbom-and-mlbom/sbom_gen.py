"""Generate a CycloneDX-style SBOM with an ML-BOM entry, and validate it. Offline, stdlib only.

What you get
    build_bom(env, timestamp)   a dict shaped like a CycloneDX 1.5 JSON document:
                                  - software components  (type "library", with purl, hashes, licenses)
                                  - a model component    (type "machine-learning-model", with a modelCard)
                                  - dataset components   (type "data")
                                  - a dependency graph
    validate_bom(bom)           structural checks that mirror what a policy gate wants

IMPORTANT: this is a teaching subset written from memory of the CycloneDX format. It is not
validated against the official JSON schema. For real work, generate with a maintained tool
(cyclonedx-py, Syft, Trivy, ...) and validate with the CycloneDX schema. Check the spec at
https://cyclonedx.org for field names in the version you use.

Usage:
    python sbom_gen.py [fixture_env.json] > bom.json
"""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC_VERSION = "1.5"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PURL = re.compile(r"^pkg:[a-z]+/[^@\s]+@[^\s]+$")
# A few SPDX identifiers; real validation uses the full SPDX list.
KNOWN_LICENSES = {"MIT", "Apache-2.0", "BSD-3-Clause", "MPL-2.0", "CC-BY-4.0", "GPL-3.0-only"}


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"


def _license(lic: str) -> list[dict]:
    if lic in KNOWN_LICENSES:
        return [{"license": {"id": lic}}]
    return [{"license": {"name": lic}}]  # not an SPDX id: CycloneDX uses "name"


def _hash(sha: str) -> list[dict]:
    return [{"alg": "SHA-256", "content": sha}]


def build_bom(env: dict, timestamp: str = "2026-01-01T00:00:00Z") -> dict:
    app = env["application"]
    app_ref = f"app:{app['name']}@{app['version']}"
    components: list[dict] = []
    deps: list[dict] = []

    for p in env["packages"]:
        ref = purl(p["name"], p["version"])
        components.append({
            "type": "library", "bom-ref": ref, "name": p["name"], "version": p["version"],
            "purl": ref, "hashes": _hash(p["sha256"]), "licenses": _license(p["license"]),
        })
    by_name = {p["name"]: purl(p["name"], p["version"]) for p in env["packages"]}
    for p in env["packages"]:
        deps.append({"ref": by_name[p["name"]], "dependsOn": [by_name[r] for r in p["requires"] if r in by_name]})

    m = env["model"]
    model_ref = f"model:{m['name']}@{m['version']}"
    dataset_refs = []
    for d in m["datasets"]:
        dref = f"dataset:{d['name']}@{d['version']}"
        dataset_refs.append(dref)
        components.append({
            "type": "data", "bom-ref": dref, "name": d["name"], "version": d["version"],
            "hashes": _hash(d["sha256"]), "licenses": _license(d["license"]),
            "data": [{"type": "dataset", "name": d["name"],
                      "classification": "contains personal data" if d.get("contains_pii") else "no personal data"}],
        })
    base = m["base_model"]
    base_ref = f"model:{base['name']}@{base['version']}"
    components.append({
        "type": "machine-learning-model", "bom-ref": base_ref, "name": base["name"],
        "version": base["version"], "hashes": _hash(base["sha256"]),
    })
    components.append({
        "type": "machine-learning-model", "bom-ref": model_ref, "name": m["name"], "version": m["version"],
        "hashes": _hash(m["sha256"]), "licenses": _license(m["license"]),
        "modelCard": {
            "modelParameters": {
                "task": m["task"], "architectureFamily": m["architecture"],
                "datasets": [{"ref": r} for r in dataset_refs],
            },
            "considerations": {
                "useCases": [m["intended_use"]], "technicalLimitations": [m["limitations"]],
            },
        },
    })
    deps.append({"ref": model_ref, "dependsOn": [base_ref] + dataset_refs})
    deps.append({"ref": app_ref, "dependsOn": list(by_name[n] for n in env["app_requires"]) + [model_ref]})

    return {
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, app_ref + timestamp)),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "caisp-lab-sbom-gen", "version": "0.1"}],
            "component": {"type": "application", "bom-ref": app_ref, "name": app["name"], "version": app["version"]},
        },
        "components": components,
        "dependencies": deps,
    }


def validate_bom(bom: dict) -> list[str]:
    """Return a list of problems. An empty list means the BOM passes this lab's policy."""
    problems: list[str] = []
    if bom.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be CycloneDX")
    if not str(bom.get("specVersion", "")).startswith("1."):
        problems.append("specVersion missing or unsupported")
    if not str(bom.get("serialNumber", "")).startswith("urn:uuid:"):
        problems.append("serialNumber must be a urn:uuid")
    if "timestamp" not in bom.get("metadata", {}):
        problems.append("metadata.timestamp missing")

    comps = bom.get("components", [])
    refs = [c.get("bom-ref") for c in comps] + [bom.get("metadata", {}).get("component", {}).get("bom-ref")]
    for r in sorted({r for r in refs if refs.count(r) > 1}, key=str):
        problems.append(f"duplicate bom-ref: {r}")
    known = set(refs)

    for c in comps:
        who = f"{c.get('type')} {c.get('name')}"
        for key in ("type", "bom-ref", "name"):
            if not c.get(key):
                problems.append(f"{who}: missing {key}")
        for h in c.get("hashes", []):
            if h.get("alg") != "SHA-256" or not HEX64.match(h.get("content", "")):
                problems.append(f"{who}: bad hash")
        if c.get("type") == "library":
            if not PURL.match(c.get("purl", "")):
                problems.append(f"{who}: bad or missing purl")
            if not c.get("hashes"):
                problems.append(f"{who}: no hash")
            if not c.get("licenses"):
                problems.append(f"{who}: no license")
        if c.get("type") == "machine-learning-model" and c.get("modelCard"):
            if not c.get("hashes"):
                problems.append(f"{who}: model has no hash")
            if not c.get("licenses"):
                problems.append(f"{who}: model has no license")
            ds = c["modelCard"].get("modelParameters", {}).get("datasets", [])
            if not ds:
                problems.append(f"{who}: model card lists no training dataset")
            for d in ds:
                if d.get("ref") not in known:
                    problems.append(f"{who}: dataset ref {d.get('ref')} is not a component")
            if not c["modelCard"].get("considerations", {}).get("useCases"):
                problems.append(f"{who}: model card has no intended use")
        if c.get("type") == "data" and not c.get("licenses"):
            problems.append(f"{who}: dataset has no license")

    for dep in bom.get("dependencies", []):
        if dep.get("ref") not in known:
            problems.append(f"dependency ref {dep.get('ref')} is not a component")
        for t in dep.get("dependsOn", []):
            if t not in known:
                problems.append(f"dependsOn target {t} is not a component")
    return problems


def main(argv: list[str]) -> int:
    path = Path(argv[0]) if argv else HERE / "fixture_env.json"
    bom = build_bom(json.loads(path.read_text(encoding="utf-8")))
    print(json.dumps(bom, indent=2))
    problems = validate_bom(bom)
    for p in problems:
        print("PROBLEM:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
