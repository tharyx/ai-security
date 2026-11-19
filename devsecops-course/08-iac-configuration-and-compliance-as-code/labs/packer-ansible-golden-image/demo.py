"""From repo root:
    .venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/packer-ansible-golden-image/demo.py
"""
import json
import secrets
from pathlib import Path

import packer_lab as pk

FIX = Path(__file__).parent / "fixtures"
for name in ("golden.pkr.hcl", "golden_bad.pkr.hcl"):
    found = pk.validate(pk.parse_hcl((FIX / name).read_text()))
    print(f"== {name}: {len(found)} finding(s) ==")
    for f in found:
        print(f"  [{f.severity:8}] {f.rule_id} {f.where}: {f.message}")

manifest = pk.simulate_build(FIX / "golden.pkr.hcl")
print("\nSimulated manifest.json:")
print(json.dumps(manifest, indent=2)[:900], "...")

key = secrets.token_bytes(32)  # stand-in for a signing key held by the CI system
att = pk.sign_manifest(manifest, key)
good = pk.validate(pk.parse_hcl((FIX / "golden.pkr.hcl").read_text()))
comp = json.loads((FIX / "compliance_result.json").read_text())["score"]
scan = json.loads((FIX / "scan_result.json").read_text())
gate = pk.promotion_gate(manifest, good, comp, scan, att, key)
print(f"\nPromotion gate: {gate.decision} {gate.reasons}")

manifest["builds"][0]["artifact_id"] = "sha256:" + "0" * 64  # tamper
gate = pk.promotion_gate(manifest, good, comp, scan, att, key)
print(f"After tampering: {gate.decision} {gate.reasons}")
