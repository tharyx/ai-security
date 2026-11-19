"""Container snapshots: `docker commit`, `docker save`, layer diffs (no Docker needed).

An image is a stack of layers. `docker commit` turns a container's writable layer into a new layer on top of the
image. `docker save` writes a tar holding manifest.json, a config JSON and one tar per layer. If you can read
those tars you can diff two snapshots and see exactly which files were added, changed or removed.

A layer here is a dict {"created_by": str, "files": {path: content-or-None}}. None means a whiteout (a delete).
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import dataclass

SUSPICIOUS_PATHS = (
    "/etc/cron", "/var/spool/cron", "/etc/profile.d/", "/root/.ssh/", "/etc/ld.so.preload", "/etc/sudoers",
    "/usr/local/bin/", "/tmp/.", "/etc/rc.local", "/etc/systemd/system/",
)
WHITEOUT = ".wh."


def sha256(data: bytes | str) -> str:
    data = data.encode() if isinstance(data, str) else data
    return "sha256:" + hashlib.sha256(data).hexdigest()


def commit(base_layers: list[dict], container_changes: dict[str, str | None], message: str = "docker commit") -> list[dict]:
    """Simulate `docker commit`: the writable layer becomes a new top layer."""
    return base_layers + [{"created_by": message, "files": dict(container_changes)}]


def make_layer_tar(files: dict[str, str | None]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path, content in sorted(files.items()):
            name = path.lstrip("/")
            if content is None:  # whiteout marker file, as in the OCI image spec
                head, _, tail = name.rpartition("/")
                name = f"{head + '/' if head else ''}{WHITEOUT}{tail}"
                content = ""
            raw = content.encode()
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(raw), 0  # fixed mtime makes layer digests reproducible
            tar.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def save(layers: list[dict], repo_tag: str) -> bytes:
    """Simulate `docker save`: a tar with manifest.json, config JSON and layer tars."""
    layer_tars = [make_layer_tar(layer["files"]) for layer in layers]
    diff_ids = [sha256(t) for t in layer_tars]
    config = {"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": diff_ids},
              "history": [{"created_by": layer["created_by"]} for layer in layers]}
    config_raw = json.dumps(config, sort_keys=True).encode()
    config_name = sha256(config_raw).split(":")[1] + ".json"
    layer_names = [d.split(":")[1] + "/layer.tar" for d in diff_ids]
    manifest = [{"Config": config_name, "RepoTags": [repo_tag], "Layers": layer_names}]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def put(name: str, raw: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
        put("manifest.json", json.dumps(manifest).encode())
        put(config_name, config_raw)
        for name, raw in zip(layer_names, layer_tars):
            put(name, raw)
    return buf.getvalue()


@dataclass
class SavedImage:
    repo_tags: list[str]
    history: list[str]
    diff_ids: list[str]
    layers: list[dict[str, str | None]]  # per layer {path: content or None for whiteout}


def load(tar_bytes: bytes) -> SavedImage:
    """Read what `docker save` wrote. Never extracts to disk: reads members into memory only."""
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        manifest = json.loads(tar.extractfile("manifest.json").read())[0]
        config = json.loads(tar.extractfile(manifest["Config"]).read())
        layers = []
        for name in manifest["Layers"]:
            files: dict[str, str | None] = {}
            with tarfile.open(fileobj=io.BytesIO(tar.extractfile(name).read())) as ltar:
                for member in ltar.getmembers():
                    base = member.name.rpartition("/")[2]
                    path = "/" + member.name
                    if base.startswith(WHITEOUT):
                        path = "/" + member.name.replace(base, base[len(WHITEOUT):])
                        files[path] = None
                    else:
                        files[path] = ltar.extractfile(member).read().decode()
            layers.append(files)
    return SavedImage(manifest["RepoTags"], [h["created_by"] for h in config["history"]],
                      config["rootfs"]["diff_ids"], layers)


def flatten(layers: list[dict[str, str | None]]) -> dict[str, str]:
    """Union file system: later layers win; None removes the file."""
    merged: dict[str, str] = {}
    for layer in layers:
        files = layer["files"] if "created_by" in layer else layer  # accept layer dicts or bare file maps
        for path, content in files.items():
            if content is None:
                merged.pop(path, None)
            else:
                merged[path] = content
    return merged


def diff(old: dict[str, str], new: dict[str, str]) -> dict[str, list[str]]:
    return {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "modified": sorted(p for p in set(old) & set(new) if old[p] != new[p]),
    }


def suspicious(paths: list[str]) -> list[str]:
    return [p for p in paths if p.startswith(SUSPICIOUS_PATHS)]


def layer_listing(image: SavedImage) -> list[str]:
    out = []
    for i, (digest, files) in enumerate(zip(image.diff_ids, image.layers)):
        out.append(f"layer {i} {digest[:19]}... {len(files)} file(s) ({image.history[i]})")
    return out
