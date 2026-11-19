"""Run the breakout checker on two team submissions. Offline, fictional system."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import breakout as b  # noqa: E402

FIX = HERE / "fixtures"
system = b.load(FIX / "system.json")
key = b.load(FIX / "answer_key.json")

print(f"System: {system['name']}")
print("Trust-boundary crossings:")
for c in b.boundary_crossings(system):
    print(f"  {c['flow']}: {c['from']} -> {c['to']} ({'inbound' if c['inbound'] else 'outbound'})")
print("External attack surface (entry points):")
for s in b.attack_surface(system):
    print(f"  {s}")
print()
# Usage: demo.py [path/to/your_team.json]  (no argument = the two sample teams)
files = [Path(a) for a in sys.argv[1:]] or [FIX / "submissions" / t for t in ("team_a.json", "team_b.json")]
for path in files:
    print(b.render(b.check(b.load(path), key, system)))
    print()
