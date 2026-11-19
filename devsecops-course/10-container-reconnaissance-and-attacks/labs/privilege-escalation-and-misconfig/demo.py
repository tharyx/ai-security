import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import privesc

FIX = Path(__file__).parent / "fixtures"
for name in ("host", "host-rootless"):
    host = json.loads((FIX / f"{name}.json").read_text())
    print(f"== {name}.json ==")
    for c in privesc.analyze_host(host):
        print(f"  [{c.severity:<8}] {c.who}")
        for step in c.chain:
            print("      ->", step)
    print("  misconfigurations:", privesc.misconfiguration_checklist(host) or "none")
    print()
