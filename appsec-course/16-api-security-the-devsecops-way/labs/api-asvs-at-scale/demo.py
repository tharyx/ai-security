import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import asvs_api as a  # noqa: E402

REQ = a.load(HERE / "fixtures/asvs_api_requirements.json")["requirements"]
INV = a.load(HERE / "fixtures/api_inventory.json")
EV = a.load(HERE / "fixtures/evidence.json")

print("1. Inventory hygiene (problems that break security at scale)")
for f in a.inventory_findings(INV):
    print("   -", f)

print("\n2. Portfolio view")
print(f"   {'api':16} {'L':>2} {'reqs':>5} {'pass':>5} {'fail':>5} {'untested':>9} {'manual':>7} {'verified':>9} gate")
for r in a.portfolio(INV, REQ, EV):
    print(f"   {r['api']:16} {r['level']:>2} {r['requirements']:>5} {r['pass']:>5} {r['fail']:>5} {r['untested']:>9} "
          f"{r['manual']:>7} {r['verified_pct']:>8}% {'FAIL' if r['gate'] else 'ok'}")

print("\n3. Checklist for orders-api (Markdown, first rows)")
orders = next(x for x in INV if x["name"] == "orders-api")
md = a.to_markdown(orders, a.evaluate(orders, REQ, EV["orders-api"]))
print("\n".join("   " + line for line in md.splitlines()[:12]))
