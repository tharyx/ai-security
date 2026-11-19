import json
import pathlib
from datetime import date

import pytest

from aisec_lab import load_lab_module

vm = load_lab_module(__file__, "vm_policy")
FX = pathlib.Path(__file__).parent / "fixtures" / "findings.json"
TODAY = date(2026, 11, 19)


def load():
    out = []
    for r in json.loads(FX.read_text()):
        out.append(vm.Finding(id=r["id"], title=r["title"], severity=r["severity"],
                              found=date.fromisoformat(r["found"]), component=r["component"], kev=r["kev"],
                              epss=r["epss"], status=r.get("status", "active"),
                              mitigated=date.fromisoformat(r["mitigated"]) if r.get("mitigated") else None))
    return out


@pytest.fixture
def t():
    return vm.Tracker(load())


def test_default_sla_days():
    assert vm.DEFAULT_SLA == {"Critical": 7, "High": 30, "Medium": 90, "Low": 120}


def test_due_dates(t):
    assert t.policy.due_date(t.findings[1]) == date(2026, 10, 8)
    assert t.policy.due_date(t.findings[2]) == date(2026, 11, 9)


def test_kev_gets_tighter_sla(t):
    f = t.findings[6]
    assert t.policy.sla_for(f) == 3 and t.policy.due_date(f) == date(2026, 11, 13)


def test_sla_status(t):
    assert t.sla_status(t.findings[1], TODAY) == "breached"
    assert t.sla_status(t.findings[5], TODAY) == "within-sla"   # found 2026-09-15 + 90d
    assert t.sla_status(t.findings[7], TODAY) == "n/a"          # mitigated


def test_sla_boundary_is_inclusive(t):
    f = t.findings[1]
    assert t.sla_status(f, date(2026, 10, 8)) == "within-sla"
    assert t.sla_status(f, date(2026, 10, 9)) == "breached"


def test_overdue_sorted_by_due_date(t):
    ids = [f.id for f in t.overdue(TODAY)]
    assert ids == [1, 4, 3, 2, 6]


def test_info_has_no_sla():
    t = vm.Tracker([vm.Finding(1, "x", "Info", date(2026, 1, 1))])
    assert t.sla_status(t.findings[1], TODAY) == "no-sla"


def test_risk_acceptance_removes_from_active(t):
    t.accept_risk(3, owner="a", approver="b", justification="ok", today=TODAY, days=90)
    assert t.findings[3].status == "risk_accepted"
    assert 3 not in [f.id for f in t.overdue(TODAY)]


@pytest.mark.parametrize("kw,msg", [
    (dict(justification=" ", days=30), "justification"),
    (dict(justification="x", days=0), "expire"),
    (dict(justification="x", days=365), "expire"),
])
def test_risk_acceptance_rules(t, kw, msg):
    with pytest.raises(vm.PolicyError, match=msg):
        t.accept_risk(3, owner="a", approver="b", today=TODAY, **kw)


def test_approver_must_differ_from_owner(t):
    with pytest.raises(vm.PolicyError, match="different"):
        t.accept_risk(3, owner="a", approver="a", justification="x", today=TODAY, days=30)


def test_kev_cannot_be_risk_accepted(t):
    with pytest.raises(vm.PolicyError, match="known-exploited"):
        t.accept_risk(6, owner="a", approver="b", justification="x", today=TODAY, days=30)


def test_expired_acceptance_reactivates_and_stays_overdue(t):
    t.accept_risk(3, owner="a", approver="b", justification="x", today=TODAY, days=30)
    assert t.sweep_expired(date(2026, 12, 19)) == []          # exactly on the expiry day
    assert t.sweep_expired(date(2026, 12, 20)) == [3]
    assert t.findings[3].status == "active"
    assert t.sla_status(t.findings[3], date(2026, 12, 20)) == "breached"  # clock was never reset


def test_false_positive_needs_reason_and_second_person(t):
    with pytest.raises(vm.PolicyError):
        t.mark_false_positive(4, reporter="a", reviewer="a", reason="r", today=TODAY)
    with pytest.raises(vm.PolicyError):
        t.mark_false_positive(4, reporter="a", reviewer="b", reason="", today=TODAY)
    t.mark_false_positive(4, reporter="a", reviewer="b", reason="test only", today=TODAY)
    assert t.findings[4].status == "false_positive"
    assert t.open_by_severity()["Low"] == 0


def test_open_by_severity(t):
    assert t.open_by_severity() == {"Critical": 1, "High": 2, "Medium": 2, "Low": 1, "Info": 0}


def test_mttr(t):
    # #7: found 09-01, mitigated 09-20 = 19 days; #8: found 08-01, mitigated 09-20 = 50 days
    assert t.mttr_days()["High"] == 34.5
    assert t.mttr_days()["Critical"] is None


def test_sla_compliance(t):
    assert t.sla_compliance() == 50.0   # #7 within 30d, #8 not


def test_mitigate_updates_metrics(t):
    t.mitigate(1, date(2026, 10, 5))
    assert t.mttr_days()["Critical"] == 4.0
    assert t.open_by_severity()["Critical"] == 0


def test_audit_trail_written(t):
    t.accept_risk(3, owner="a", approver="b", justification="x", today=TODAY, days=30)
    t.mitigate(1, TODAY)
    assert len(t.audit) == 2


def test_summary_shape(t):
    s = t.summary(TODAY)
    assert set(s) == {"open_by_severity", "mttr_days", "sla_compliance_pct", "overdue", "risk_accepted"}
