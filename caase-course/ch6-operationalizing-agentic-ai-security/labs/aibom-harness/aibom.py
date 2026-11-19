"""AI/Agent Bill of Materials (AIBOM) for an agent harness, CycloneDX-style JSON.

A harness is more than code. Its AIBOM lists: the model (and provider), tools,
MCP servers, skills, prompts, and library dependencies, each with a version and
a content hash where we can compute one. The output follows the SHAPE of
CycloneDX 1.6 (bomFormat, specVersion, serialNumber, components with bom-ref,
type, name, version, hashes, licenses, purl, properties, plus a dependencies
graph). It is NOT checked against the official JSON schema here: for real use,
validate with the CycloneDX tooling and check the spec version at
cyclonedx.org (verify at source).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path

FLOATING = re.compile(r"^(latest|\*|main|master|head|)$|^[\^~><]", re.I)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _comp(ref: str, ctype: str, name: str, version: str, kind: str, **extra) -> dict:
    c = {"bom-ref": ref, "type": ctype, "name": name, "version": version, "properties": [{"name": "caase:kind", "value": kind}]}
    c.update(extra)
    return c


def build_aibom(manifest: dict, base_dir: Path, timestamp: str = "2026-01-01T00:00:00Z") -> dict:
    comps: list[dict] = []
    root_ref = f"harness:{manifest['name']}@{manifest['version']}"
    deps: list[str] = []

    m = manifest["model"]
    ref = f"model:{m['name']}@{m['version']}"
    comps.append(
        _comp(ref, "machine-learning-model", m["name"], m["version"], "model",
              supplier={"name": m["provider"]},
              licenses=[{"license": {"id": m["license"]}}] if m.get("license") else [],
              hashes=[{"alg": "SHA-256", "content": m["sha256"]}] if m.get("sha256") else [])
    )
    deps.append(ref)

    for t in manifest.get("tools", []):
        ref = f"tool:{t['name']}@{t['version']}"
        comps.append(_comp(ref, "library", t["name"], t["version"], "tool",
                           hashes=[{"alg": "SHA-256", "content": sha256_text(t["description"])}]))
        deps.append(ref)

    for s in manifest.get("mcp_servers", []):
        ref = f"mcp:{s['name']}@{s['version']}"
        comps.append(_comp(ref, "application", s["name"], s["version"], "mcp-server", purl=s.get("purl", ""),
                           properties=[{"name": "caase:kind", "value": "mcp-server"}, {"name": "caase:transport", "value": s["transport"]}],
                           hashes=[{"alg": "SHA-256", "content": s["sha256"]}] if s.get("sha256") else []))
        deps.append(ref)

    for kind, key, ctype in (("skill", "skills", "file"), ("prompt", "prompts", "data")):
        for it in manifest.get(key, []):
            ref = f"{kind}:{it['name']}@{it.get('version', '0')}"
            comps.append(_comp(ref, ctype, it["name"], it.get("version", "0"), kind,
                               hashes=[{"alg": "SHA-256", "content": sha256_file(base_dir / it["path"])}]))
            deps.append(ref)

    for d in manifest.get("dependencies", []):
        ref = f"lib:{d['name']}@{d['version']}"
        comps.append(_comp(ref, "library", d["name"], d["version"], "library", purl=d.get("purl", "")))
        deps.append(ref)

    core = json.dumps([root_ref, [c["bom-ref"] for c in comps], [c.get("hashes") for c in comps]], sort_keys=True)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, core)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {"bom-ref": root_ref, "type": "application", "name": manifest["name"], "version": manifest["version"]},
        },
        "components": comps,
        "dependencies": [{"ref": root_ref, "dependsOn": deps}],
    }


def validate(bom: dict) -> list[str]:
    """Structural checks. Returns a list of problems (empty = ok)."""
    errs: list[str] = []
    if bom.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be CycloneDX")
    if not str(bom.get("specVersion", "")).startswith("1."):
        errs.append("specVersion missing or unsupported")
    if not str(bom.get("serialNumber", "")).startswith("urn:uuid:"):
        errs.append("serialNumber must be a urn:uuid")
    refs: set[str] = set()
    comps = bom.get("components") or []
    if not comps:
        errs.append("no components")
    kinds = set()
    for c in comps:
        for f in ("bom-ref", "type", "name", "version"):
            if not c.get(f):
                errs.append(f"component {c.get('name', '?')}: missing {f}")
        if c.get("bom-ref") in refs:
            errs.append(f"duplicate bom-ref {c['bom-ref']}")
        refs.add(c.get("bom-ref"))
        if FLOATING.search(str(c.get("version", ""))):
            errs.append(f"{c.get('name')}: floating version '{c.get('version')}' (pin it)")
        for h in c.get("hashes", []):
            if h.get("alg") != "SHA-256" or not HEX64.match(h.get("content", "")):
                errs.append(f"{c.get('name')}: malformed hash")
        for p in c.get("properties", []):
            if p.get("name") == "caase:kind":
                kinds.add(p["value"])
        if c.get("type") == "machine-learning-model" and not c.get("licenses"):
            errs.append(f"{c.get('name')}: model has no license recorded")
    if "model" not in kinds:
        errs.append("harness AIBOM must contain a model component")
    for dep in bom.get("dependencies", []):
        for r in dep.get("dependsOn", []):
            if r not in refs:
                errs.append(f"dependency on unknown ref {r}")
    return errs


def diff(old: dict, new: dict) -> dict[str, list[str]]:
    """What changed between two AIBOMs (use it in CI to flag silent model/skill/prompt swaps)."""
    o = {c["bom-ref"].rsplit("@", 1)[0]: c for c in old["components"]}
    n = {c["bom-ref"].rsplit("@", 1)[0]: c for c in new["components"]}
    changed = [k for k in o.keys() & n.keys() if o[k]["version"] != n[k]["version"] or o[k].get("hashes") != n[k].get("hashes")]
    return {"added": sorted(n.keys() - o.keys()), "removed": sorted(o.keys() - n.keys()), "changed": sorted(changed)}
