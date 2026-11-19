"""From repo root:
    .venv/Scripts/python devsecops-course/08-iac-configuration-and-compliance-as-code/labs/inspec-compliance-profile/demo.py
"""
import json
from pathlib import Path

import inspec_lite as il

HERE = Path(__file__).parent
profile = il.load_profile(HERE / "profile")
print(f"Profile {profile.meta['name']} {profile.meta['version']}: {len(profile.controls)} controls, check errors: {il.check_profile(profile)}")

for name in ("host_compliant.json", "host_drifted.json"):
    facts = json.loads((HERE / "fixtures" / name).read_text())
    res = il.run_profile(profile, facts)
    s = il.summarize(res)
    print(f"\n== {facts['hostname']} ==  {s}")
    for r in res:
        if r["status"] == "failed":
            print(f"  FAIL [{il.severity(r['impact'])}] {r['id']} {r['title']}")
            for x in r["results"]:
                if x["status"] == "failed":
                    print(f"       {x['code_desc']}  ({x['message']})")

print("\n=== At scale: 20 fake hosts ===")
baseline = json.loads((HERE / "fixtures" / "host_compliant.json").read_text())
fleet = il.generate_fleet(baseline, n=20, seed=7)
print(il.render_fleet(il.scan_fleet(profile, fleet)))
