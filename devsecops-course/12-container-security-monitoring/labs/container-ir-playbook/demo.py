"""Run the IR runbook against a fake docker. From repo root:
    .venv/Scripts/python devsecops-course/12-container-security-monitoring/labs/container-ir-playbook/demo.py
"""
import json
import tempfile
from pathlib import Path

import ir_playbook as ir

HERE = Path(__file__).parent
inc = json.loads((HERE / "fixtures" / "incident.json").read_text())
rb = ir.load_runbook(HERE / "runbook.yaml")
d = ir.FakeDocker(inc)
with tempfile.TemporaryDirectory() as tmp:
    res = ir.run_playbook(rb, inc, d, Path(tmp) / inc["case"])
    print("commands in order:")
    for i, c in enumerate(res["commands"], 1):
        print(f"  {i:>2}. {c}")
    print("evidence manifest (sha256):")
    for f, h in sorted(res["manifest"].items()):
        print(f"  {h[:16]}...  {f}")
print("network list after isolate:", d.networks, "| paused:", d.paused)

print("--- guard: redeploying the same image digest is refused ---")
bad = dict(inc, clean_image_digest=inc["image_digest"])
with tempfile.TemporaryDirectory() as tmp:
    try:
        ir.run_playbook(rb, bad, ir.FakeDocker(bad), Path(tmp))
    except ir.PlaybookError as e:
        print("refused:", e)
