import json
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sbscan  # noqa: E402

FIX = HERE / "fixtures"
cfg = json.loads((FIX / "triage.json").read_text())
today = date(2026, 11, 19)

bugs = sbscan.parse(FIX / "spotbugsXml.xml")
print(f"== parsed {len(bugs)} bug instances from spotbugsXml.xml")

active, dropped = sbscan.triage(bugs, cfg, today)
print("\n== dropped by triage")
for b, why in dropped:
    print(f"  {b.type:24} {b.cls}.{b.method}  -> {why}")

print("\n== active findings (worst first)")
for b in active:
    flag = f"  [{b.status}: {b.reason}]" if b.status != "open" else ""
    print(f"  rank {b.rank:<2} {sbscan.label(b.rank):10} {b.type:24} CWE-{b.cwe}  {b.path}:{b.line}{flag}")

print("\n== grouped by CWE")
for k, v in sbscan.group_by_cwe(active).items():
    print(f"  {k}: {len(v)}")

print("\n== gate")
print("fail on rank <= 9  -> exit", sbscan.gate(active, 9))
print("fail on rank <= 4  -> exit", sbscan.gate(active, 4))

sarif = sbscan.parse(FIX / "results.sarif")
same = {(b.type, b.cls, b.line) for b in sarif} == {(b.type, b.cls, b.line) for b in bugs}
print("\nSARIF and XML describe the same bugs:", same)
