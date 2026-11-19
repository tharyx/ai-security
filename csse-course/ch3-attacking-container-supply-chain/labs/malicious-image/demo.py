"""Inspect a clean and a malicious-style image config. From repo root:
    .venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/malicious-image/demo.py
"""
from pathlib import Path

import inspector as ins

FIX = Path(__file__).parent / "fixtures"
for name, cfg, layers in [("clean", "config_clean.json", None), ("malicious", "config_malicious.json", "layers_malicious.json")]:
    found = ins.inspect_files_path(FIX / cfg, FIX / layers if layers else None)
    print(f"== {name}: {ins.verdict(found)} ({len(found)} finding(s)) ==")
    for f in found:
        print(f"  [{f.severity:8}] {f.rule_id} {f.where}: {f.message}")
