"""Commit a container, save it, diff the snapshots. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/container-snapshots/demo.py
"""
import json
from pathlib import Path

import snapshot as sn

FIX = Path(__file__).parent / "fixtures"
base = json.loads((FIX / "base_layers.json").read_text())
changes = json.loads((FIX / "container_changes.json").read_text())["files"]

v1 = sn.load(sn.save(base["layers"], base["repo_tag"]))
v2 = sn.load(sn.save(sn.commit(base["layers"], changes, "docker commit shop-container"), "shop-api:1.0-snapshot"))

print("== v1 layers ==")
print("\n".join(sn.layer_listing(v1)))
print("== v2 layers (after docker commit) ==")
print("\n".join(sn.layer_listing(v2)))
d = sn.diff(sn.flatten(v1.layers), sn.flatten(v2.layers))
for kind in ("added", "modified", "removed"):
    print(f"{kind}: {d[kind]}")
print("suspicious additions:", sn.suspicious(d["added"]))
print("first two layer digests unchanged:", v1.diff_ids == v2.diff_ids[:2])
