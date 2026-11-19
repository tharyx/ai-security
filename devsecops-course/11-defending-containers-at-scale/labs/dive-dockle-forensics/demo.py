"""Forensics on a leaky image and a Dockle-like checklist. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/dive-dockle-forensics/demo.py
"""
import json
from pathlib import Path

import layer_forensics as lf

FIX = Path(__file__).parent / "fixtures"
for name in ("image_leaky.json", "image_clean.json"):
    img = json.loads((FIX / name).read_text())
    print(f"== {name}")
    for d in lf.deleted_but_present(img):
        print(f"  deleted-but-present: {d['path']} added in {d['added_in']}, removed in {d['removed_in']}, content={d['content'].strip()!r}")
    for s in lf.find_secrets(img):
        print(f"  secret in {s['layer']} ({s['created_by']}): {s['path']} in_final_image={s['in_final_image']}")
    eff, wasted = lf.efficiency(img)
    print(f"  dive-style efficiency: {eff}% ({wasted} wasted bytes)")
    for i, lvl, msg in lf.dockle(img):
        print(f"  dockle {lvl:<5} {i}: {msg}")
