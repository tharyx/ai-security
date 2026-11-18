"""Demo: ingest four log sources, normalize, run the YAML rules, print the alerts.

Run:  python cybersecurity-track/06-siem-sentinel-splunk/lab/demo.py
"""

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import minisiem  # noqa: E402  (demo.py may import siblings)


def main() -> None:
    events = minisiem.ingest()
    print("INGEST: normalized events per source:", dict(Counter(e.source for e in events)))
    print("        total:", len(events), "events, one common schema\n")
    rules = minisiem.load_rules()
    print(f"RULES: {len(rules)} loaded: " + ", ".join(r["id"] for r in rules) + "\n")
    alerts = minisiem.run_all(rules, events)
    print(f"{'TIME (UTC)':21} {'LEVEL':7} {'ATT&CK':16} {'ENTITY':38} {'EVENTS':>6}  TITLE")
    print("-" * 125)
    for a in alerts:
        ent = ",".join(f"{k}={v}" for k, v in a.entity.items() if v)
        print(f"{a.time:21} {a.level:7} {','.join(a.attack):16} {ent:38} {a.count:>6}  {a.title}")
    print(f"\n{len(alerts)} alerts from {len(events)} events")


if __name__ == "__main__":
    main()
