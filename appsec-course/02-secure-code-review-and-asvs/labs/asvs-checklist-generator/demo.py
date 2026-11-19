import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import asvs_checklist as ac  # noqa: E402

FIX = HERE / "fixtures"
reqs = ac.load_sample(FIX / "asvs5_sample.json")
print(f"sample requirements loaded: {len(reqs)}")

for prof_file in ("profile_partner_api.json", "profile_shop.json"):
    prof = json.loads((FIX / prof_file).read_text(encoding="utf-8"))
    items = ac.select(reqs, prof["level"], prof["features"])
    print(f"\n{prof['name']}: level {prof['level']}, {len(items)} requirements apply")
    print("  ids:", ", ".join(i["id"] for i in items))

prof = json.loads((FIX / "profile_shop.json").read_text(encoding="utf-8"))
results = json.loads((FIX / "results_shop.json").read_text(encoding="utf-8"))
items = ac.apply_results(ac.select(reqs, prof["level"], prof["features"]), results)
print()
print(ac.to_markdown(items, prof["name"]))
print("\nsummary:", ac.summary(items))
print("gate exit code:", ac.gate(items))
print("\nCSV (first 3 lines):")
print("\n".join(ac.to_csv(items).splitlines()[:3]))
