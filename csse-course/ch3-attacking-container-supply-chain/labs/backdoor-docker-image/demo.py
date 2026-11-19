"""Backdoor detection by layer diff and digest pin. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/backdoor-docker-image/demo.py
"""
import json
from pathlib import Path

import verify as v

FIX = Path(__file__).parent / "fixtures"
orig = json.loads((FIX / "original.json").read_text())
bad = json.loads((FIX / "backdoored.json").read_text())

store = v.TagStore()
pin = store.push("shop-api:1.0", orig)
pins = {"shop-api:1.0": pin}
print("pinned digest      :", pin[:30] + "...")
store.push("shop-api:1.0", bad)  # attacker re-pushes the same tag
pulled = store.pull_by_tag("shop-api:1.0")
print("tag after re-push  : shop-api:1.0 (same name!)")
print("pull by tag        :", "no check, runs new content")
ok, why = v.verify_pin("shop-api:1.0", pulled, pins)
print("pull by pinned digest:", "OK" if ok else "REFUSED", "-", why)

d = v.diff_images(orig, pulled)
print("added layers       :", d.added_layers)
print("added files        :", d.added_files)
print("autorun locations  :", v.autorun_additions(d))
print("canary hits        :", v.find_canaries(pulled))
