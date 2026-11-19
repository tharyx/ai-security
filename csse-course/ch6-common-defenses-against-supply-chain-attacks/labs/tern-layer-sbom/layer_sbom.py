"""Tern-style layer-by-layer SBOM: attribute each package to the Dockerfile instruction (layer) that added it."""

from __future__ import annotations

IMAGE = {
    "name": "shop/api:1.4",
    "layers": [
        {"id": "sha256:l1", "created_by": "FROM debian:12-slim (base)", "base": True,
         "packages": {"libc6": "2.36-9+deb12u7", "bash": "5.2.15-2+b7"}},
        {"id": "sha256:l2", "created_by": "RUN apt-get update && apt-get install -y curl openssl", "base": False,
         "packages": {"libc6": "2.36-9+deb12u7", "bash": "5.2.15-2+b7", "curl": "7.88.1-10+deb12u5", "openssl": "3.0.13-1~deb12u1"}},
        {"id": "sha256:l3", "created_by": "RUN apt-get install -y --only-upgrade openssl && apt-get purge -y curl", "base": False,
         "packages": {"libc6": "2.36-9+deb12u7", "bash": "5.2.15-2+b7", "openssl": "3.0.14-1~deb12u1"}},
        {"id": "sha256:l4", "created_by": "COPY . /app (no package manager)", "base": False,
         "packages": {"libc6": "2.36-9+deb12u7", "bash": "5.2.15-2+b7", "openssl": "3.0.14-1~deb12u1"}},
    ],
}


def layer_deltas(image: dict):
    """Compare each layer's package snapshot with the previous layer. Returns one report dict per layer."""
    prev: dict[str, str] = {}
    reports = []
    for layer in image["layers"]:
        cur = layer["packages"]
        added = {k: v for k, v in cur.items() if k not in prev}
        removed = {k: v for k, v in prev.items() if k not in cur}
        changed = {k: (prev[k], cur[k]) for k in cur if k in prev and prev[k] != cur[k]}
        reports.append({"layer": layer["id"], "created_by": layer["created_by"], "base": layer["base"],
                        "added": added, "removed": removed, "changed": changed})
        prev = cur
    return reports


def attribution(image: dict) -> dict:
    """Map each package in the final image to the layer that introduced its current version."""
    owner: dict[str, str] = {}
    for r in layer_deltas(image):
        for k in list(r["added"]) + list(r["changed"]):
            owner[k] = r["layer"]
        for k in r["removed"]:
            owner.pop(k, None)
    final = image["layers"][-1]["packages"]
    return {k: {"version": v, "layer": owner[k]} for k, v in final.items()}


def base_vs_added(image: dict) -> dict:
    base_layers = {l["id"] for l in image["layers"] if l["base"]}
    attr = attribution(image)
    base = sorted(k for k, v in attr.items() if v["layer"] in base_layers)
    return {"from_base_image": base, "added_by_you": sorted(set(attr) - set(base))}


def layers_without_packages(image: dict):
    return [r["layer"] for r in layer_deltas(image) if not (r["added"] or r["removed"] or r["changed"])]


def deleted_but_present_in_history(image: dict):
    """Packages removed in a later layer still exist in earlier layers: scanners must look at layers, not only the final FS."""
    seen, gone = set(), set()
    for r in layer_deltas(image):
        seen |= set(r["added"])
        gone |= set(r["removed"])
    return sorted(gone & seen)
