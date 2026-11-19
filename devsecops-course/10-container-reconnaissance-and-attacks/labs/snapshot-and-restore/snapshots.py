"""Snapshot a container for later analysis: commit vs export vs save, a diff between snapshots, and restore.

Real commands (hedged): `docker commit c img:snap`, `docker export c > fs.tar`, `docker save img:snap -o img.tar`,
`docker diff c`, `docker run img:snap`. See also csse-course ch3 labs/container-snapshots for a layer-focused twin.

Forensic habit: snapshot BEFORE you stop or remove a suspicious container, and analyse the snapshot, not the original.
"""
from __future__ import annotations

import copy
import hashlib
import json

DELETED = None  # marker for a deleted file in a diff


def digest(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:12]


class Image:
    def __init__(self, name: str, layers: list[dict], config: dict, history: list[str]):
        self.name, self.layers, self.config, self.history = name, layers, config, history

    def rootfs(self) -> dict[str, str]:
        fs: dict[str, str] = {}
        for layer in self.layers:
            for path, content in layer.items():
                if content is DELETED:
                    fs.pop(path, None)
                else:
                    fs[path] = content
        return fs


class Container:
    def __init__(self, image: Image, name: str):
        self.image, self.name = image, name
        self.fs = image.rootfs()
        self.config = copy.deepcopy(image.config)

    def write(self, path: str, content: str):
        self.fs[path] = content

    def delete(self, path: str):
        self.fs.pop(path, None)

    def diff(self) -> dict[str, str]:
        """`docker diff`: A (added), C (changed), D (deleted) relative to the image."""
        base, out = self.image.rootfs(), {}
        for p, c in self.fs.items():
            if p not in base:
                out[p] = "A"
            elif base[p] != c:
                out[p] = "C"
        for p in base:
            if p not in self.fs:
                out[p] = "D"
        return out

    # --- the three snapshot styles ---
    def commit(self, tag: str) -> Image:
        """New image = old layers + ONE new layer with the changes. Keeps config and history."""
        layer = {p: (DELETED if s == "D" else self.fs[p]) for p, s in self.diff().items()}
        return Image(tag, self.image.layers + [layer], copy.deepcopy(self.config), self.image.history + [f"commit of {self.name}"])

    def export(self) -> dict:
        """Flat file system tar: ONE blob, no layers, no history, no config (no ENV, no CMD)."""
        return {"kind": "export", "files": dict(self.fs)}


def save(image: Image) -> dict:
    """`docker save`: all layers + config + manifest, ready to `docker load` elsewhere."""
    return {"kind": "save", "name": image.name, "layers": [digest(l) for l in image.layers], "config": image.config, "history": image.history}


def snapshot_diff(a: dict[str, str], b: dict[str, str]) -> dict[str, str]:
    """Compare two flat file views (e.g. snapshot at T1 vs T2)."""
    out = {}
    for p in sorted(set(a) | set(b)):
        if p not in a:
            out[p] = "added"
        elif p not in b:
            out[p] = "deleted"
        elif a[p] != b[p]:
            out[p] = "modified"
    return out


def restore(image: Image, name: str) -> Container:
    """Start a fresh container from a snapshot image: the evidence is preserved, the original is untouched."""
    return Container(image, name)


def compare_methods(c: Container) -> dict[str, dict]:
    img = c.commit("evidence:1")
    exp = c.export()
    sv = save(img)
    return {
        "commit": {"keeps_history": True, "keeps_config": True, "keeps_layers": True, "volumes_included": False, "result": "image"},
        "export": {"keeps_history": False, "keeps_config": "env" in exp, "keeps_layers": False, "volumes_included": False, "result": "tar of files"},
        "save": {"keeps_history": bool(sv["history"]), "keeps_config": bool(sv["config"]), "keeps_layers": bool(sv["layers"]), "volumes_included": False, "result": "tar of image"},
    }
