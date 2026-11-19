import json
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mvnscan  # noqa: E402

osv = mvnscan.osv
FIX = HERE / "fixtures"
db = osv.load_db(HERE.parent / "_shared" / "advisories.osv.json")

deps, warns = mvnscan.parse_pom(FIX / "pom.xml")
print("== dependencies read from pom.xml (properties and dependencyManagement resolved)")
for d in deps:
    print(f"  {d.coord}:{d.version}  scope={d.scope}")
for w in sorted(set(warns)):
    print("WARN", w)

print("\n== CPE-style matching (Dependency-Check approach), test scope skipped")
cpe = mvnscan.scan(deps, db, mode="cpe")
print(osv.render(cpe))

print("\n== same pom with test scope included (skipTestScope=false)")
print(osv.render(mvnscan.scan(deps, db, mode="cpe", skip_test_scope=False)))

print("\n== exact coordinate matching (OSV approach)")
print(osv.render(mvnscan.scan(deps, db, mode="coordinate", skip_test_scope=False)))

print("\n== suppress the false positive, then break the build on CVSS >= 7.0")
sup = json.loads((FIX / "suppressions.json").read_text())
kept, suppressed, w = osv.apply_ignores(cpe, sup, date(2026, 11, 19))
print("suppressed:", [f"{f.advisory}/{f.package}" for f in suppressed])
print("failBuildOnCVSS=7  -> exit", mvnscan.break_build(kept, 7.0))
print("failBuildOnCVSS=9  -> exit", mvnscan.break_build(kept, 9.0))
print("failBuildOnCVSS=7, min confidence HIGHEST -> exit", mvnscan.break_build(kept, 7.0, "HIGHEST"))
