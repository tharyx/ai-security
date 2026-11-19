import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import agile_sec as a  # noqa: E402

print("== Security activities per Scrum event ==")
for event, activity in a.SCRUM_SECURITY.items():
    print(f"  {event:30} {activity}")

for name in ("backlog_weak.json", "backlog_good.json"):
    backlog = a.load(HERE / "fixtures" / name)
    problems = a.check_backlog(backlog)
    print(f"\n== {name}: {len(problems)} problems, gate exit code {a.gate(backlog)} ==")
    for p in problems:
        print("  -", p)

print("\n== Gherkin generated from the good backlog's abuse cases ==")
print(a.to_gherkin(a.load(HERE / "fixtures" / "backlog_good.json")))
