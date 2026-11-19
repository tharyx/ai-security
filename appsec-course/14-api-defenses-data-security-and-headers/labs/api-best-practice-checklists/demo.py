import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bp_checklists as bp  # noqa: E402

FX = HERE / "fixtures"
for style in ("graphql", "soap", "rest"):
    for variant in ("weak", "hardened"):
        cfg = bp.load(FX / f"{style}_{variant}.json")
        findings = bp.check(style, cfg)
        print(f"== {cfg['name']}: {len(findings)} finding(s), gate exit {bp.gate(findings)}")
        for f in findings:
            print(f"  [{f.severity}] {f.rule} {f.message}")
    print()

deep = "query { me { friends { friends { friends { friends { friends { friends { friends { name } } } } } } } } }"
brute = "mutation { " + " ".join(f'a{i}: login(user: "admin", pin: "{i:04d}") {{ ok }}' for i in range(50)) + " }"
hard = bp.load(FX / "graphql_hardened.json")
weak = bp.load(FX / "graphql_weak.json")
print("Deep query      weak:", bp.enforce_graphql_limits(deep, weak)[1], "| hardened:", bp.enforce_graphql_limits(deep, hard)[1])
print("50-alias brute  weak:", bp.enforce_graphql_limits(brute, weak)[1], "| hardened:", bp.enforce_graphql_limits(brute, hard)[1])
