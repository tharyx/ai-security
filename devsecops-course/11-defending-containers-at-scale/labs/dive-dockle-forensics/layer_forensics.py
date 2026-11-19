"""Dive-like layer forensics and a Dockle-like checklist over an image fixture.

Fixture = what `docker save` + `docker history` + `docker inspect` would give you,
shrunk to JSON: config (User, Env, Healthcheck) and ordered layers with files.
Whiteout files (".wh.<name>") are how OCI layers record a deletion: the earlier layer
still contains the file. Dockle ids (CIS-DI-xxxx / DKL-DI-xxxx) are quoted from memory
of its docs: verify at https://github.com/goodwithtech/dockle .
"""
from __future__ import annotations

import posixpath
import re

SECRET_RE = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)\s*=|BEGIN FAKE PRIVATE KEY", re.I)


def _is_whiteout(path: str) -> bool:
    return posixpath.basename(path).startswith(".wh.")


def _target(path: str) -> str:
    d, b = posixpath.split(path)
    return posixpath.join(d, b[4:])


def final_fs(image: dict) -> dict[str, dict]:
    """Merged filesystem: path -> {layer, size, mode}. Whiteouts remove earlier paths."""
    fs: dict[str, dict] = {}
    for layer in image["layers"]:
        for f in layer["files"]:
            if _is_whiteout(f["path"]):
                fs.pop(_target(f["path"]), None)
            else:
                fs[f["path"]] = {"layer": layer["id"], "size": f.get("size", 0), "mode": f.get("mode", "0644")}
    return fs


def deleted_but_present(image: dict) -> list[dict]:
    """Files removed by a later layer but still stored in the earlier one."""
    out = []
    layers = image["layers"]
    for j, lj in enumerate(layers):
        for f in lj["files"]:
            if not _is_whiteout(f["path"]):
                continue
            tgt = _target(f["path"])
            for li in layers[:j]:
                for g in li["files"]:
                    if g["path"] == tgt:
                        out.append({"path": tgt, "added_in": li["id"], "removed_in": lj["id"],
                                    "content": g.get("content", "")})
    return out


def find_secrets(image: dict) -> list[dict]:
    """Secret-looking content in ANY layer; says whether the final filesystem still has it."""
    live = final_fs(image)
    out = []
    for layer in image["layers"]:
        for f in layer["files"]:
            if SECRET_RE.search(f.get("content", "")):
                still = live.get(f["path"], {}).get("layer") == layer["id"]
                out.append({"path": f["path"], "layer": layer["id"], "in_final_image": still,
                            "recoverable": True, "created_by": layer["created_by"]})
    return out


def efficiency(image: dict) -> tuple[float, int]:
    """Dive-style: wasted bytes = files overwritten or deleted by later layers."""
    seen: dict[str, int] = {}
    wasted = total = 0
    for layer in image["layers"]:
        for f in layer["files"]:
            size = f.get("size", 0)
            total += size
            if _is_whiteout(f["path"]):
                wasted += seen.pop(_target(f["path"]), 0)
            else:
                wasted += seen.get(f["path"], 0)
                seen[f["path"]] = size
    return (round(100 * (1 - wasted / total), 1) if total else 100.0, wasted)


def dockle(image: dict) -> list[tuple[str, str, str]]:
    """(id, level, message); level FATAL/WARN/INFO like Dockle's own output."""
    cfg, fs, out = image["config"], final_fs(image), []
    if cfg.get("User", "") in ("", "root", "0"):
        out.append(("CIS-DI-0001", "WARN", "Last user should not be root"))
    if not any(e.startswith("DOCKER_CONTENT_TRUST=1") for e in cfg.get("Env", [])):
        out.append(("CIS-DI-0005", "INFO", "Enable Content trust (retired DCT: prefer cosign/Notation verification)"))
    if not cfg.get("Healthcheck"):
        out.append(("CIS-DI-0006", "WARN", "Not found HEALTHCHECK statement"))
    suid = [p for p, m in fs.items() if int(m["mode"], 8) & 0o6000]
    if suid:
        out.append(("CIS-DI-0008", "WARN", "setuid/setgid files: " + ", ".join(sorted(suid))))
    if any(l["created_by"].startswith("ADD ") for l in image["layers"]):
        out.append(("CIS-DI-0009", "WARN", "Use COPY instead of ADD"))
    bad_env = [e.split("=")[0] for e in cfg.get("Env", []) if SECRET_RE.search(e)]
    if bad_env:
        out.append(("CIS-DI-0010", "FATAL", "Secrets in ENV: " + ", ".join(bad_env)))
    if "usr/bin/sudo" in fs:
        out.append(("DKL-DI-0001", "WARN", "Avoid sudo command"))
    if any(p.startswith("var/lib/apt/lists/") for p in fs):
        out.append(("DKL-DI-0005", "INFO", "Clear apt-get caches"))
    return out
