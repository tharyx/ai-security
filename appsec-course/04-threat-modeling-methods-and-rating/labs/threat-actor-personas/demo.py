"""Threat actor personas + ATT&CK mapping for the ShopCo model. Offline, fictional."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import personas as p  # noqa: E402

FIX = HERE / "fixtures"
tech = {k: v for k, v in p.load(FIX / "attack_techniques.json").items() if not k.startswith("_")}
people = p.load(FIX / "personas.json")["personas"]
threats = p.load(FIX / "threats.json")["threats"]
titles = {t["id"]: t["title"] for t in threats}

print(p.card(people[1], tech))
print()
for persona in people:
    rel = p.relevant_threats(persona, threats)
    print(f"{persona['name']} (skill {persona['skill']}): {', '.join(rel) or 'none'}")
print()
print("Threats with no ATT&CK mapping (model them anyway):")
for tid in p.unmapped_threats(threats):
    print(f"  {tid} {titles[tid]}")
print("Mapped threats no persona would attempt (missing persona?):")
for tid in p.uncovered_threats(people, threats):
    print(f"  {tid} {titles[tid]}")
