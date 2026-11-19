import json
import pathlib
from datetime import date

import vm_policy as vm

raw = json.loads((pathlib.Path(__file__).parent / "fixtures" / "findings.json").read_text())
findings = [vm.Finding(id=r["id"], title=r["title"], severity=r["severity"],
                       found=date.fromisoformat(r["found"]), component=r["component"], kev=r["kev"],
                       epss=r["epss"], status=r.get("status", "active"),
                       mitigated=date.fromisoformat(r["mitigated"]) if r.get("mitigated") else None)
            for r in raw]
today = date(2026, 11, 19)
t = vm.Tracker(findings)

print("SLA status today:")
for f in findings:
    print(f"  #{f.id} {f.severity:8} due={t.policy.due_date(f)} -> {t.sla_status(f, today)}")

t.accept_risk(3, owner="app-team", approver="ciso", justification="behind VPN; fix in Q1",
              today=today, days=90)
t.mark_false_positive(4, reporter="dev", reviewer="appsec", reason="test fixture only", today=today)
try:
    t.accept_risk(6, owner="app-team", approver="ciso", justification="later", today=today, days=30)
except vm.PolicyError as e:
    print("\nKEV acceptance refused:", e)
print("\nexpired acceptances on 2027-03-01:", t.sweep_expired(date(2027, 3, 1)))
print("\nsummary:", json.dumps(t.summary(today), default=str))
print("audit:", *t.audit, sep="\n  ")
