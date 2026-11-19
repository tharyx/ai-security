import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pyscan  # noqa: E402

osv = pyscan.osv
FIX = HERE / "fixtures"
db = osv.load_db(HERE.parent / "_shared" / "advisories.osv.json")

reqs, warns = pyscan.parse_requirements(FIX / "requirements.txt")
print(f"== parsed {len(reqs)} requirements")
for w in warns:
    print("WARN", w)

findings = pyscan.scan(reqs, db)
print("\n== safety / pip-audit style findings")
print(osv.render(findings))

keep, drop = pyscan.reachability(findings, db, FIX / "src")
print("\n== reachability triage (heuristic, uses ast on fixtures/src)")
print("fix first:")
print(osv.render(keep))
print("deprioritise (still upgrade, but not an emergency):")
print(osv.render(drop))

print("\n== break-build gates")
print("fail-on high, all findings       -> exit", osv.gate(findings, "high"))
print("fail-on high, reachable only     -> exit", osv.gate(keep, "high"))
print("fail-on critical, reachable only -> exit", osv.gate(keep, "critical"))
print("fail-on low, anything at all     -> exit", osv.gate(findings, "low"))
