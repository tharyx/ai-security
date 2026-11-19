import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import iriuslite as ir  # noqa: E402

library = ir.load(HERE / "fixtures" / "library.json")
for name in ("multitier.json", "multicloud.json"):
    project = ir.load(HERE / "fixtures" / name)
    comps = ir.apply_questionnaire(project["components"], project["answers"])
    threats = ir.generate(comps, library)
    ir.set_states(threats, project["states"])
    print(f"== {project['name']} ==")
    for t in threats:
        print(f"  {t.component:26} {t.title[:46]:46} inherent {t.inherent:2} residual {t.residual:4}")
        for c in t.countermeasures:
            print(f"      - {c.state:14} {c.name}")
    r = ir.report(threats)
    print(f"  total inherent {r['inherent']}, residual {r['residual']} ({r['reduction_pct']}% reduced)")
    print("  required but not implemented:", r["required_not_implemented"])
    print("  gate (max residual 12) exit code:", ir.gate(threats))
    print()
