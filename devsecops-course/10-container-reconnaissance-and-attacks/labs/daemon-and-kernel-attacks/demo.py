import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import hostattacks as ha

FIX = Path(__file__).parent / "fixtures"
for name in ("daemon-bad", "daemon-good"):
    print(f"== {name}.json ==")
    findings = ha.audit_daemon(json.loads((FIX / f"{name}.json").read_text()))
    for sev, msg in findings or [("OK", "no findings")]:
        print(f"  [{sev:<8}] {msg[:105]}")
cs = json.loads((FIX / "containers.json").read_text())
print("\nFlat network:")
for f in ha.flat_network_exposure(cs):
    print("  -", f[:110])
print("\nDoS exposure (missing limits):")
for f in ha.dos_exposure(cs):
    print("  -", f)
print("\nFork-bomb concept (arithmetic only):")
for limit in (None, 200):
    r = ha.fork_growth(limit)
    print(f"  pids-limit={limit!s:<5} -> {r['final_processes']:>6} processes after {r['generations_to_cap']} generations, stopped by {r['hit']}; {r['host_impact']}")
print("\nKernel risk by host kernel version (fixture CVE list):")
for kv in ("5.4.0-150", "5.15.0-fixture", "6.8.12"):
    ids = [c["id"] for c in ha.kernel_risk(kv)]
    print(f"  {kv:<16} {ids or 'none in the fixture list'}")
