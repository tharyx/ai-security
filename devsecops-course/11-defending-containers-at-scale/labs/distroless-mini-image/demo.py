"""Rank base images by attack surface. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/distroless-mini-image/demo.py
"""
import json
from pathlib import Path

import surface as s

cat = json.loads((Path(__file__).parent / "fixtures" / "catalog.json").read_text())
for r in s.rank(cat):
    print(f"{r['surface']:>4}  {r['name']:<28} {r['size_mb']:>3} MB  pkgs={r['packages']:<3} shell={r['shell']!s:<5} tools={r['attacker_tools']}")
print("pick (no shell needed):", s.pick(cat)["name"])
print("pick (shell needed)   :", s.pick(cat, needs_shell=True)["name"])
