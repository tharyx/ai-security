import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from aisec_lab import load_lab_module  # noqa: E402

s = load_lab_module(__file__, "schedules")
here = Path(__file__).parent

for profile in s.PROFILES:
    plan = s.generate_plan(profile, "http://staging.example.test", openapi_url="http://staging.example.test/openapi.json")
    errs = s.validate_plan(plan)
    print(f"== {profile}: jobs = {[j['type'] for j in plan['jobs']]}  validator errors = {errs}")
print()
print(s.to_yaml(s.generate_plan("commit", "http://staging.example.test")))

bad = s.generate_plan("commit", "http://prod.example.com")
bad["jobs"].insert(1, {"type": "activeScan", "parameters": {"context": "app"}})
print("== deliberately bad plan ==")
for e in s.validate_plan(bad):
    print("  -", e)

print("\n== break-build gate ==")
for name, profile in (("commit_report.json", "commit"), ("weekly_report.json", "weekly")):
    alerts = s.parse_zap_report((here / "fixtures" / name).read_text())
    ok, why = s.evaluate_gate(alerts, s.POLICIES[profile])
    print(f"{name} under '{profile}' policy: {'PASS' if ok else 'FAIL'}")
    for r in why:
        print("   -", r)
pol = s.GatePolicy(fail_on="High", baseline={"40012", "40018"})
alerts = s.parse_zap_report((here / "fixtures" / "weekly_report.json").read_text())
print("weekly report with both Highs in the baseline (known debt):", "PASS" if s.evaluate_gate(alerts, pol)[0] else "FAIL")
