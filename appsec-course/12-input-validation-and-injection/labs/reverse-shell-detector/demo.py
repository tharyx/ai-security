import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import detector as d  # noqa: E402

procs = d.load(HERE / "fixtures" / "process_events.json")
flows = d.load(HERE / "fixtures" / "network_flows.json")
EGRESS = ["10.0.0.0/8"]  # app servers may only talk to internal networks

print("== Detection over simulated EDR/auditd telemetry ==")
for a in d.detect(procs, flows, EGRESS):
    print(f"[{a['severity']}] {a['host']} pid {a['pid']} {a['exe']!r} (parent {a['parent']!r})")
    for r in a["rules"]:
        print("      ", r)

print("\n== Prevention: default-deny egress would have dropped ==")
for f in d.egress_blocked(flows, EGRESS):
    print(f"   {f['host']} pid {f['pid']} -> {f['dst']}:{f['dport']}")

print("\n== Prevention: image review ==")
for m in d.load(HERE / "fixtures" / "images.json"):
    print(f"   {m['image']}: {d.image_findings(m) or ['clean']}")
