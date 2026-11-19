import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import privacy as p  # noqa: E402

for name in ("fitness_app_v1.json", "fitness_app_v2.json"):
    system = p.load(HERE / "fixtures" / name)
    threats = p.linddun(system)
    screen = p.dpia_screening(system)
    print(f"== {system['name']} ==")
    print(f"  DPIA required: {screen['required']} (criteria met: {', '.join(screen['criteria_met']) or 'none'})")
    print("  LINDDUN summary:", {k: v for k, v in p.summary(threats).items() if v} or "no threats found")
    for t in threats:
        print(f"  [{t.category}] {t.target}: {t.text}")
    reqs = p.privacy_requirements(threats)
    if reqs:
        print("  Privacy requirements for the backlog:")
        for r in reqs:
            print("   -", r)
    print()
