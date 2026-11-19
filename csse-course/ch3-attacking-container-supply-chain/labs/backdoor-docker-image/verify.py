"""Detect a backdoored image by layer diff and digest pinning.

The "backdoor" here is a harmless canary string (CANARY-BACKDOOR-...). Nothing is executed.
Idea: an attacker re-pushes the same tag with one extra layer. The tag still reads "1.0", but the digest changed.
If you pinned the digest, the pull fails verification. If you only trust the tag, you run the new content.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

CANARY_PREFIX = "CANARY-BACKDOOR"
AUTORUN_PATHS = ("/etc/profile.d/", "/etc/cron", "/usr/local/bin/", "/etc/rc.local", "/root/.bashrc", "/docker-entrypoint.d/")


def layer_digest(layer: dict) -> str:
    canonical = json.dumps(layer["files"], sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def image_digest(image: dict) -> str:
    """Stand-in for the manifest digest: a hash over the ordered layer digests plus the config."""
    body = json.dumps({"layers": [layer_digest(layer) for layer in image["layers"]], "config": image.get("config", {})},
                      sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass
class LayerDiff:
    added_layers: list[int]
    changed_layers: list[int]
    added_files: list[str]
    modified_files: list[str]
    config_changed: bool


def diff_images(old: dict, new: dict) -> LayerDiff:
    old_l, new_l = old["layers"], new["layers"]
    changed = [i for i in range(min(len(old_l), len(new_l))) if layer_digest(old_l[i]) != layer_digest(new_l[i])]
    added = list(range(len(old_l), len(new_l)))
    old_files = {p: c for layer in old_l for p, c in layer["files"].items()}
    added_files, modified = [], []
    for i in added + changed:
        for path, content in new_l[i]["files"].items():
            if path not in old_files:
                added_files.append(path)
            elif old_files[path] != content:
                modified.append(path)
    return LayerDiff(added, changed, sorted(set(added_files)), sorted(set(modified)),
                     old.get("config", {}) != new.get("config", {}))


def find_canaries(image: dict) -> list[tuple[int, str]]:
    return [(i, path) for i, layer in enumerate(image["layers"]) for path, content in layer["files"].items()
            if CANARY_PREFIX in (content or "")]


def autorun_additions(diff: LayerDiff) -> list[str]:
    return [p for p in diff.added_files + diff.modified_files if p.startswith(AUTORUN_PATHS)]


def verify_pin(reference: str, image: dict, pins: dict[str, str]) -> tuple[bool, str]:
    """reference is name:tag. Returns (ok, reason). Unpinned references are refused in strict mode by the caller."""
    if reference not in pins:
        return False, f"{reference} has no pinned digest (tag trust only)"
    actual = image_digest(image)
    if actual != pins[reference]:
        return False, f"digest mismatch: pinned {pins[reference][:19]}... but got {actual[:19]}..."
    return True, "digest matches pin"


class TagStore:
    """A toy registry tag table, to show that a tag is a movable label and a digest is not."""

    def __init__(self) -> None:
        self.tags: dict[str, dict] = {}

    def push(self, ref: str, image: dict) -> str:
        self.tags[ref] = image
        return image_digest(image)

    def pull_by_tag(self, ref: str) -> dict:
        return self.tags[ref]
