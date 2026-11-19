"""Demo: inventory + advisory matching, days exposed, SLA, and the timeline."""

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exposure as x  # noqa: E402

assets, advs = x.load(Path(__file__).parent / "fixtures")
breach = date(2017, 5, 13)
findings, gaps = x.find_vulnerabilities(assets, advs, breach)

print(f"Inventory: {len(assets)} assets. Advisories: {len(advs)}. Checked on {breach}.\n")
print("FINDINGS (vulnerable and still unpatched):")
for f in findings:
    print(f"  {f.asset} ({f.host}) runs {f.component} {f.version}: {f.advisory} [{f.severity}]")
    print(f"    internet-facing={f.internet_facing}  fixed in {', '.join(f.fixed_in)}  owner={f.owner}")
    print(f"    advisory published {f.advisory_date}; days exposed = {f.days_exposed}; "
          f"SLA = {f.sla_days} days; SLA breached = {f.sla_breached}")

print("\nINVENTORY GAPS (what you cannot match, you cannot patch):")
for g in gaps:
    print(f"  {g.asset} ({g.host}): {g.problem}")

print("\nTIMELINE (days after the advisory):")
for name, day, delta in x.timeline(advs[0], "2017-03-15", "2017-05-13", "2017-07-29", "2017-08-01"):
    print(f"  {day}  +{delta:>3}d  {name}")

fixed, _ = x.find_vulnerabilities(assets, advs, breach, patched_on={"dispute-portal": "2017-03-08"})
print(f"\nWhat if the patch had shipped on 2017-03-08? days exposed = {fixed[0].days_exposed}, "
      f"SLA breached = {fixed[0].sla_breached}")
