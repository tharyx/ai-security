import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import jsscan  # noqa: E402

osv = jsscan.osv
FIX = HERE / "fixtures"
db = osv.load_db(HERE.parent / "_shared" / "advisories.osv.json")

print("== npm audit style (package-lock.json)")
audit = jsscan.npm_audit(jsscan.load_lock(FIX / "package-lock.json"), db)
print(osv.render(audit))

print("\n== npm audit --omit=dev")
print(osv.render(jsscan.npm_audit(jsscan.load_lock(FIX / "package-lock.json"), db, omit_dev=True)))

print("\n== RetireJS style (files under webapp/)")
retire = jsscan.retire_scan(FIX / "webapp", jsscan.load_extractors(FIX / "retire_extractors.json"), db)
for f in retire:
    print(f"[{f.severity:8}] {f.advisory} {f.package}@{f.version} in {f.path[0]} ({f.note})")

print("\n== who found what")
for k, v in jsscan.compare(retire, audit).items():
    print(f"{k:12}", sorted(v))

print("\n== break-build gate (today = 2026-11-19)")
import json  # noqa: E402
ignores = json.loads((FIX / "ignores.json").read_text())
every = osv.sort_findings(audit + retire)
kept, suppressed, warnings = osv.apply_ignores(every, ignores, date(2026, 11, 19))
for w in warnings:
    print("WARN", w)
print("suppressed:", [f"{f.advisory}/{f.package}" for f in suppressed])
for level in ("critical", "high", "medium"):
    print(f"fail-on {level:8} -> exit", osv.gate(kept, fail_on=level))
print("fail-cvss 9.0     -> exit", osv.gate(kept, fail_on="critical", fail_cvss=9.0))

print("\n== after upgrading acme-templ and fakequery (only the MEDIUM chartlet finding is left)")
left = [f for f in kept if f.severity == "MEDIUM"]
for level in ("critical", "high", "medium"):
    print(f"fail-on {level:8} -> exit", osv.gate(left, fail_on=level))
