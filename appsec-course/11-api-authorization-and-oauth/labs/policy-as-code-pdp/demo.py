import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pdp  # noqa: E402

policy = pdp.load_policy(HERE / "fixtures" / "policy.json")
cases = json.loads((HERE / "fixtures" / "policy_tests.json").read_text(encoding="utf-8"))

print("== Policy tests (like `opa test`) ==")
fails = pdp.run_policy_tests(policy, cases)
print(f"{len(cases) - len(fails)}/{len(cases)} passed")
for f in fails:
    print("FAIL", f)

print("\n== API handler asks the PDP ==")
alice = {"id": "u-alice", "roles": ["rider"]}
for trip in ("t-1", "t-2"):
    status, body, d = pdp.pep_get_trip(policy, alice, trip)
    print(f"GET /trips/{trip} as alice -> {status} matched={d.matched} reason={d.reason!r}")

print("\n== Change behaviour by changing policy, not code ==")
stricter = json.loads(json.dumps(policy))
stricter["rules"] = [r for r in stricter["rules"] if r["id"] != "support-reads-trips-in-own-region"]
sam = {"id": "u-sam", "roles": ["support"], "region": "south"}
print("support reads t-1 (old policy):", pdp.pep_get_trip(policy, sam, "t-1")[0])
print("support reads t-1 (new policy):", pdp.pep_get_trip(stricter, sam, "t-1")[0])

print("\n== Lint catches a typo before deploy ==")
bad = {"default": "deny", "rules": [{"id": "x", "effect": "allow", "actions": ["*"], "when": [["subject.id", "=", "u-1"]]}]}
try:
    pdp.lint(bad)
except pdp.PolicyError as e:
    print("PolicyError:", e)
