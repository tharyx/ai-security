"""A Dive-like layer inspector plus a Trivy/Grype-like package check, over image layer fixtures.

What the real tools do (hedged, verify at source):
- Dive: shows each layer's file changes and an "image efficiency" score (wasted space from files that are
  overwritten or removed in later layers).
- Trivy / Grype: match installed packages against vulnerability databases; Trivy can also find secrets.
Here the "image" is a dict: layers (created_by + files) and a package list. Secrets are canaries built at runtime.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


def canary_token() -> str:
    """A fake token that cannot match a real provider format (built from pieces at runtime)."""
    return "dso" + "-fake-" + "token-" + "c0ffee12"


def canary_key_block() -> str:
    head = "-----" + "BEGIN " + "FAKE-CANARY " + "KEY-----"
    tail = "-----" + "END " + "FAKE-CANARY " + "KEY-----"
    return f"{head}\nZmFrZS1jYW5hcnktbm90LWEtcmVhbC1rZXk=\n{tail}"


def sample_image() -> dict:
    return {
        "name": "shop/api:1.4",
        "layers": [
            {"created_by": "FROM debian:12-slim", "files": {"/bin/sh": {"size": 120_000}, "/usr/lib/libbase.so": {"size": 30_000_000}}},
            {"created_by": "RUN apt-get update && apt-get install -y curl", "files": {"/var/lib/apt/lists/pkg": {"size": 25_000_000}, "/usr/bin/curl": {"size": 250_000}}},
            {"created_by": "COPY secrets/ /app/secrets/", "files": {
                "/app/secrets/id_key": {"size": 200, "content": canary_key_block()},
                "/app/.env": {"size": 80, "content": "API_TOKEN=" + canary_token() + "\nDEBUG=1\n"},
            }},
            {"created_by": "COPY . /app", "files": {"/app/app.py": {"size": 4_000}, "/app/data.bin": {"size": 8_000_000}}},
            {"created_by": "RUN rm -rf /var/lib/apt/lists/* /app/secrets", "files": {
                "/var/lib/apt/lists/.wh.pkg": {"size": 0}, "/app/secrets/.wh.id_key": {"size": 0}}},
            {"created_by": "COPY data-v2.bin /app/data.bin", "files": {"/app/data.bin": {"size": 8_500_000}}},
        ],
        "packages": [
            {"name": "openssl", "version": "3.0.9"}, {"name": "libwebp", "version": "1.2.0"},
            {"name": "curl", "version": "8.9.1"}, {"name": "zlib", "version": "1.3"},
        ],
    }


VULN_DB = [  # fixture, FAKE ids on purpose
    {"id": "FIXTURE-0001", "package": "openssl", "fixed_in": "3.0.13", "severity": "HIGH", "summary": "fixture: memory read in TLS handshake"},
    {"id": "FIXTURE-0002", "package": "libwebp", "fixed_in": "1.3.2", "severity": "CRITICAL", "summary": "fixture: heap overflow in image decode"},
    {"id": "FIXTURE-0003", "package": "curl", "fixed_in": "8.9.1", "severity": "MEDIUM", "summary": "fixture: already fixed in this version"},
]


def _ver(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v))


def effective_fs(img: dict) -> dict[str, tuple[int, int]]:
    """Final file view: path -> (size, layer index). Whiteouts remove files."""
    fs: dict[str, tuple[int, int]] = {}
    for i, layer in enumerate(img["layers"]):
        for path, meta in layer["files"].items():
            d, _, base = path.rpartition("/")
            if base.startswith(".wh."):
                fs.pop(f"{d}/{base[4:]}", None)
            else:
                fs[path] = (meta["size"], i)
    return fs


def efficiency(img: dict) -> dict:
    """Wasted bytes = bytes in layers that a later layer overwrote or deleted (still shipped, never visible)."""
    total = sum(m["size"] for l in img["layers"] for m in l["files"].values())
    final = effective_fs(img)
    visible = sum(s for s, _ in final.values())
    wasted = total - visible
    per_layer = []
    for i, layer in enumerate(img["layers"]):
        w = sum(m["size"] for p, m in layer["files"].items() if p in final and final[p][1] != i
                or (not p.rsplit("/", 1)[1].startswith(".wh.") and p not in final))
        per_layer.append({"layer": i, "created_by": layer["created_by"], "size": sum(m["size"] for m in layer["files"].values()), "wasted": w})
    return {"total": total, "visible": visible, "wasted": wasted, "score": round(visible / total, 3) if total else 1.0, "layers": per_layer}


SECRET_PATTERNS = [
    ("private key block", re.compile("-----BEGIN " + r"[A-Z\- ]*KEY-----")),
    ("fake token", re.compile(r"dso-fake-token-[0-9a-f]+")),
    ("password assignment", re.compile(r"(?i)(password|passwd|secret|api_?key|token)\s*[=:]\s*\S+")),
]


def find_secrets(img: dict) -> list[dict]:
    """Scan EVERY layer, including files a later layer deleted: layers never forget."""
    final = effective_fs(img)
    out = []
    for i, layer in enumerate(img["layers"]):
        for path, meta in layer["files"].items():
            content = meta.get("content")
            if not content:
                continue
            for label, rx in SECRET_PATTERNS:
                if rx.search(content):
                    out.append({"layer": i, "path": path, "kind": label, "still_visible": path in final and final[path][1] == i,
                                "created_by": layer["created_by"]})
                    break
    return out


def vulnerable_packages(img: dict, db: list[dict] = VULN_DB) -> list[dict]:
    hits = []
    for p in img["packages"]:
        for v in db:
            if v["package"] == p["name"] and _ver(p["version"]) < _ver(v["fixed_in"]):
                hits.append({"package": p["name"], "installed": p["version"], "fixed_in": v["fixed_in"], "id": v["id"], "severity": v["severity"]})
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(hits, key=lambda h: order[h["severity"]])
