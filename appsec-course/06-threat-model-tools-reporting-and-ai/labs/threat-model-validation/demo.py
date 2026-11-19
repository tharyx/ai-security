import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import validate as v  # noqa: E402

FIX = HERE / "fixtures"
model, inventory, results = v.load(FIX / "model.json"), v.load(FIX / "inventory.json"), v.load(FIX / "test_results.json")
TODAY = date(2026, 11, 19)

for title, problems in [("1. Threat model versus reality", v.model_vs_reality(model, inventory)),
                        ("2. All threats accounted for", v.accounted_for(model, TODAY)),
                        ("3. Mitigations are tested", v.mitigations_tested(model, results))]:
    print(f"== {title}: {len(problems)} problems ==")
    for p in problems:
        print("  -", p)
    print()

print("== 4. Are we done threat modeling? ==")
done = v.are_we_done(model, inventory, results, TODAY)
for k, ok in done.items():
    print(f"  [{'x' if ok else ' '}] {k}")
print("  gate exit code:", v.gate(done))
