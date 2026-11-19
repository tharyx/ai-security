"""Read an OpenAPI spec and do recon: list endpoints, auth schemes, and find
shadow / zombie / undocumented endpoints by comparing the spec to a live
inventory.

Covers the CASP 2 lines "Understanding APIs Using OpenAPI Specifications" and
"Performing Reconnaissance on an API". OpenAPI specs are read as JSON (valid
OpenAPI; no PyYAML needed). The "live inventory" stands in for what you would
learn from crawling the running API, JavaScript bundles and old docs.

Terms:
* **documented**  : in the spec and still served.
* **shadow**      : served but NOT in the spec (undocumented; often unprotected).
* **zombie**      : in the spec but no longer served (stale docs; an old version).

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Endpoint:
    method: str
    path: str
    secured: bool
    security_schemes: tuple = ()


def load_spec(path: str | Path) -> dict:
    spec = json.loads(Path(path).read_text(encoding="utf-8"))
    if "openapi" not in spec:
        raise ValueError("not an OpenAPI 3.x document (missing 'openapi')")
    major = spec["openapi"].split(".")[0]
    if major != "3":
        raise ValueError(f"unsupported OpenAPI version {spec['openapi']!r}; expected 3.x")
    return spec


def auth_schemes(spec: dict) -> dict:
    """Return the declared security schemes (name -> type/scheme)."""
    comps = spec.get("components", {}).get("securitySchemes", {})
    out = {}
    for name, scheme in comps.items():
        label = scheme.get("type", "?")
        if scheme.get("scheme"):
            label += f"/{scheme['scheme']}"
        out[name] = label
    return out


def endpoints(spec: dict) -> list:
    """Flatten paths x methods into Endpoint records, noting security."""
    global_security = spec.get("security", [])
    result = []
    for path, item in spec.get("paths", {}).items():
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            sec = op.get("security", global_security)
            schemes = tuple(sorted(k for entry in sec for k in entry))
            result.append(Endpoint(method.upper(), path, secured=bool(sec),
                                    security_schemes=schemes))
    return result


def _key(method: str, path: str) -> tuple:
    return (method.upper(), path)


def recon(spec: dict, live_inventory: list) -> dict:
    """Compare the spec to a live (method, path) inventory.

    Returns dicts of documented / shadow / zombie endpoints.
    """
    documented_set = {_key(e.method, e.path) for e in endpoints(spec)}
    live_set = {_key(m, p) for m, p in live_inventory}
    shadow = sorted(live_set - documented_set)
    zombie = sorted(documented_set - live_set)
    documented = sorted(documented_set & live_set)
    return {"documented": documented, "shadow": shadow, "zombie": zombie}


def unauthenticated_endpoints(spec: dict) -> list:
    """Endpoints the spec marks as needing no auth (recon priority targets)."""
    return [e for e in endpoints(spec) if not e.secured]


def versioned_paths(spec: dict) -> set:
    """Collect version prefixes like v1, v2 that appear in paths (recon surface)."""
    import re
    versions = set()
    for e in endpoints(spec):
        for m in re.findall(r"/v(\d+)\b", e.path):
            versions.add(f"v{m}")
    return versions


def report(spec: dict, live_inventory: list) -> str:
    rec = recon(spec, live_inventory)
    lines = ["# API recon report", ""]
    lines.append(f"auth schemes: {auth_schemes(spec)}")
    lines.append(f"versions in spec: {sorted(versioned_paths(spec))}")
    lines.append("")
    lines.append("## Endpoints (spec)")
    for e in endpoints(spec):
        marker = "secured" if e.secured else "PUBLIC"
        lines.append(f"  {e.method:6} {e.path:30} {marker} {list(e.security_schemes)}")
    lines.append("")
    lines.append(f"## Shadow (served, undocumented): {rec['shadow']}")
    lines.append(f"## Zombie (documented, gone):     {rec['zombie']}")
    return "\n".join(lines)
