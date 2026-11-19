"""Syft-style container SBOM from an image filesystem listing fixture (dpkg / apk database text). Offline."""

from __future__ import annotations

import re

DPKG_STATUS = """\
Package: libc6
Status: install ok installed
Version: 2.36-9+deb12u7
Architecture: amd64
Source: glibc

Package: openssl
Status: install ok installed
Version: 3.0.13-1~deb12u1
Architecture: amd64

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0
Architecture: amd64
"""

APK_INSTALLED = """\
P:musl
V:1.2.5-r0
A:x86_64
L:MIT

P:busybox
V:1.36.1-r29
A:x86_64
L:GPL-2.0-only

"""

IMAGE_FS = {
    "/etc/os-release": 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
    "/var/lib/dpkg/status": DPKG_STATUS,
    "/usr/local/lib/python3.12/site-packages/flask-3.0.3.dist-info/METADATA": "Name: Flask\nVersion: 3.0.3\n",
    "/app/node_modules/left-pad/package.json": '{"name": "left-pad", "version": "1.3.0"}',
    "/app/main.py": "print('app')",
}
ALPINE_FS = {
    "/etc/os-release": 'ID=alpine\nVERSION_ID=3.20.1\n',
    "/lib/apk/db/installed": APK_INSTALLED,
}


def parse_os_release(text: str) -> dict:
    return {k: v.strip('"') for k, v in (l.split("=", 1) for l in text.splitlines() if "=" in l)}


def _stanzas(text: str):
    for block in re.split(r"\n\s*\n", text.strip()):
        yield dict(l.split(": ", 1) for l in block.splitlines() if ": " in l)


def parse_dpkg(text: str):
    return [{"name": s["Package"], "version": s["Version"], "arch": s.get("Architecture", "")}
            for s in _stanzas(text) if s.get("Status", "").endswith(" installed")]


def parse_apk(text: str):
    out = []
    for block in re.split(r"\n\s*\n", text.strip()):
        kv = dict(l.split(":", 1) for l in block.splitlines() if ":" in l)
        if "P" in kv:
            out.append({"name": kv["P"], "version": kv["V"], "arch": kv.get("A", ""), "license": kv.get("L")})
    return out


def scan_image(fs: dict) -> dict:
    """Return {os, packages: [{ecosystem, name, version, purl, location}]}."""
    osr = parse_os_release(fs.get("/etc/os-release", ""))
    distro = f"{osr.get('ID', 'unknown')}-{osr.get('VERSION_ID', '')}"
    pkgs = []
    if "/var/lib/dpkg/status" in fs:
        for p in parse_dpkg(fs["/var/lib/dpkg/status"]):
            pkgs.append({"ecosystem": "deb", "name": p["name"], "version": p["version"],
                         "purl": f"pkg:deb/{osr.get('ID')}/{p['name']}@{p['version']}?arch={p['arch']}&distro={distro}",
                         "location": "/var/lib/dpkg/status"})
    if "/lib/apk/db/installed" in fs:
        for p in parse_apk(fs["/lib/apk/db/installed"]):
            pkgs.append({"ecosystem": "apk", "name": p["name"], "version": p["version"],
                         "purl": f"pkg:apk/{osr.get('ID')}/{p['name']}@{p['version']}?arch={p['arch']}&distro={distro}",
                         "location": "/lib/apk/db/installed"})
    for path, text in fs.items():
        m = re.search(r"/site-packages/([^/]+)-([\d.]+)\.dist-info/METADATA$", path)
        if m:
            pkgs.append({"ecosystem": "pypi", "name": m.group(1).lower(), "version": m.group(2),
                         "purl": f"pkg:pypi/{m.group(1).lower()}@{m.group(2)}", "location": path})
        m = re.search(r"/node_modules/([^/]+)/package.json$", path)
        if m:
            import json
            d = json.loads(text)
            pkgs.append({"ecosystem": "npm", "name": d["name"], "version": d["version"],
                         "purl": f"pkg:npm/{d['name']}@{d['version']}", "location": path})
    return {"os": osr, "packages": sorted(pkgs, key=lambda p: (p["ecosystem"], p["name"]))}


def to_cyclonedx(image_name: str, result: dict) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "container", "name": image_name,
                                   "properties": [{"name": "os", "value": result["os"].get("PRETTY_NAME", result["os"].get("ID", ""))}]}},
        "components": [{"type": "library", "bom-ref": p["purl"], "name": p["name"], "version": p["version"], "purl": p["purl"],
                        "properties": [{"name": "location", "value": p["location"]}]} for p in result["packages"]],
    }
