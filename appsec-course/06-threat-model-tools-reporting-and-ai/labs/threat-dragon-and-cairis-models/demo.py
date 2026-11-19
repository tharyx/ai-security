import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cairis_explore as cx  # noqa: E402
import tdmodel as td  # noqa: E402

FIX = HERE / "fixtures"
print("== OWASP Threat Dragon 2.x-style model: fixtures/threat_dragon_shop.json ==")
model = td.load(FIX / "threat_dragon_shop.json")
print("  summary:", td.summary(model))
print("  validation problems:")
for p in td.validate(model):
    print("   -", p)
print("  open High threats:")
for name, kind, title in td.open_threats(model, "High"):
    print(f"   - {name}: [{kind}] {title}")

print("\n== Exploring a completed CAIRIS-style model: fixtures/cairis_clinic.xml ==")
root = cx.load(FIX / "cairis_clinic.xml")
print("  environments:", cx.environments(root))
print("  risks (likelihood x severity):")
for r in cx.risks(root):
    print(f"   - {r.score:2}  {r.name} [{r.environment}] asset={r.asset}")
print("  attacker paths:")
for p in cx.attacker_paths(root):
    print("   -", p)
print("  assets at risk with no requirement or countermeasure:", cx.unprotected_assets(root))
print("  persona tasks touching high-risk assets:")
for p in cx.persona_tasks_at_risk(root):
    print("   -", p)

print("\n== XML safety ==")
try:
    cx.safe_parse('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///lab/canary.txt">]><x>&e;</x>')
except ValueError as e:
    print("  rejected:", e)
