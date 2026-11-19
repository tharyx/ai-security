import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model_shop  # noqa: E402
import pytmlite  # noqa: E402

print("== 1. Threat model WITH code (model_shop.py, first draft) ==")
draft = model_shop.build(secure=False)
findings = draft.process()
for f in findings:
    print(f"  {f.severity:6} {f.sid:6} {f.target:17} {f.stride}")
print("  model checks:", draft.check() or "ok")
print("  gate exit code:", pytmlite.gate(findings))

print("\n== 2. Threat model AS code (fixtures/shop_model.json, same system as data) ==")
declarative = pytmlite.load_model(HERE / "fixtures" / "shop_model.json")
same = {f.key for f in declarative.process()} == {f.key for f in findings}
print("  same findings as the Python model:", same)

print("\n== 3. Custom report template (templates/exec_summary.md) ==")
print(draft.report((HERE / "templates" / "exec_summary.md").read_text(encoding="utf-8")))

print("== 4. Custom CSV template (templates/findings.csv), first 4 lines ==")
csv = draft.report((HERE / "templates" / "findings.csv").read_text(encoding="utf-8"))
print("\n".join(csv.splitlines()[:4]))

print("\n== 5. Diagrams as code: PlantUML sequence diagram ==")
print(draft.seq())

print("\n== 6. After the sprint: controls added (build(secure=True)) ==")
fixed = model_shop.build(secure=True)
print("  findings:", len(fixed.process()), "| gate exit code:", pytmlite.gate(fixed.findings))
