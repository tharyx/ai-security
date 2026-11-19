"""Syft-style application SBOM from lockfile fixtures, emitted as CycloneDX 1.5 JSON. Offline, stdlib only."""

from __future__ import annotations

import hashlib
import json
import re
import uuid

SAMPLE_REQUIREMENTS = """\
# pinned runtime dependencies
flask==3.0.3
requests==2.32.3 --hash=sha256:aaaa1111
jinja2==3.1.4
urllib3>=2.0   # not pinned: will be flagged
"""

SAMPLE_NPM_LOCK = {
    "name": "demo-web",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo-web", "version": "1.0.0"},
        "node_modules/express": {"version": "4.19.2", "integrity": "sha512-EXAMPLEINTEGRITYEXPRESS", "license": "MIT"},
        "node_modules/@scope/util": {"version": "2.1.0", "integrity": "sha512-EXAMPLEINTEGRITYUTIL", "dev": True},
        "node_modules/express/node_modules/qs": {"version": "6.11.0", "license": "BSD-3-Clause"},
    },
}


def parse_requirements(text: str):
    comps, unpinned = [], []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+!]+)(?:\s+--hash=(\w+:\w+))?", line)
        if m:
            comps.append({"ecosystem": "pypi", "name": m.group(1).lower(), "version": m.group(2), "hash": m.group(3)})
        else:
            unpinned.append(line)
    return comps, unpinned


def parse_npm_lock(lock: dict):
    comps = []
    for path, meta in lock.get("packages", {}).items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        comps.append({"ecosystem": "npm", "name": name, "version": meta["version"], "hash": meta.get("integrity"),
                      "license": meta.get("license"), "scope": "optional" if meta.get("dev") else "required",
                      "direct": path.count("node_modules/") == 1})
    return comps


def purl(c) -> str:
    name = c["name"]
    if c["ecosystem"] == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    return f"pkg:{c['ecosystem']}/{name}@{c['version']}"


def to_cyclonedx(app_name: str, app_version: str, components, deterministic: bool = True) -> dict:
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{app_name}@{app_version}") if deterministic else uuid.uuid4()
    out = []
    for c in sorted(components, key=lambda c: (c["ecosystem"], c["name"], c["version"])):
        comp = {"type": "library", "bom-ref": purl(c), "name": c["name"], "version": c["version"], "purl": purl(c),
                "scope": c.get("scope", "required")}
        if c.get("hash") and ":" in c["hash"]:
            alg, val = c["hash"].split(":", 1)
            comp["hashes"] = [{"alg": {"sha256": "SHA-256"}.get(alg, alg.upper()), "content": val}]
        if c.get("license"):
            comp["licenses"] = [{"license": {"id": c["license"]}}]
        out.append(comp)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{serial}", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "offline-syft-twin", "version": "0.1"}]},
                     "component": {"type": "application", "name": app_name, "version": app_version}},
        "components": out,
    }


def validate(doc: dict) -> list[str]:
    """Minimal structural checks (a real validator uses the CycloneDX JSON schema)."""
    errs = []
    if doc.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be CycloneDX")
    if not str(doc.get("serialNumber", "")).startswith("urn:uuid:"):
        errs.append("serialNumber must be a urn:uuid")
    refs = set()
    for c in doc.get("components", []):
        for k in ("type", "name", "bom-ref"):
            if k not in c:
                errs.append(f"component missing {k}")
        if c.get("bom-ref") in refs:
            errs.append(f"duplicate bom-ref {c.get('bom-ref')}")
        refs.add(c.get("bom-ref"))
    return errs


def build(app_name: str, requirements: str, npm_lock: dict | None = None) -> dict:
    comps, _ = parse_requirements(requirements)
    if npm_lock:
        comps += parse_npm_lock(npm_lock)
    return to_cyclonedx(app_name, "1.0.0", comps)


def sbom_digest(doc: dict) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()
