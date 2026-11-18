"""Tests for the Oracle-style audit-log analyzer.

Run from the repository root:
    .venv/Scripts/python -m pytest cybersecurity-track/11-database-security -v
"""

from datetime import datetime

from aisec_lab import load_lab_module

aa = load_lab_module(__file__, "audit_analyzer")
sa = load_lab_module(__file__, "sample_audit")

BASE = aa.build_baseline(sa.baseline_records())


def run(recs, **kw):
    kw.setdefault("service_accounts", sa.SERVICE_ACCOUNTS)
    return aa.analyze(recs, BASE, **kw)


def rules(findings):
    return [f.rule for f in findings]


def rec(ts, user, action, host=sa.DBA_HOST, program="SQL Developer", rc=0, obj=None, sql=None):
    return sa._rec(datetime.fromisoformat(ts), user, action, host, program, rc=rc, obj=obj, sql=sql)


def test_all_five_rules_fire_on_incident_night():
    assert set(rules(run(sa.incident_records()))) == {
        "PRIV_GRANT_OUTSIDE_WINDOW", "MASS_SELECT", "NEW_HOST_OR_PROGRAM", "AUDIT_TAMPERING", "ADMIN_LOGIN_BURST"}


def test_normal_app_and_in_window_grant_raise_nothing():
    normal = [r for r in sa.incident_records()
              if r["DBUSERNAME"] in ("APP_USER", "DBA_ALICE") and r["USERHOST"] != "laptop77.example"]
    assert any(r["ACTION_NAME"] == "GRANT" for r in normal)  # the benign grant is really in the data
    assert run(normal) == []


def test_baseline_period_itself_is_clean():
    assert run(sa.baseline_records()) == []


def test_grant_dba_outside_window_flagged_inside_window_not():
    out_w = rec("2026-03-11 02:00:00", "SYS", "GRANT", sql="GRANT DBA TO X")
    in_w = rec("2026-03-10 21:00:00", "SYS", "GRANT", sql="GRANT DBA TO X")  # Tuesday evening
    assert rules(run([out_w])) == ["PRIV_GRANT_OUTSIDE_WINDOW"]
    assert "PRIV_GRANT_OUTSIDE_WINDOW" not in rules(run([in_w]))


def test_ordinary_grant_is_not_privileged():
    r = rec("2026-03-11 02:00:00", "DBA_ALICE", "GRANT", sql="GRANT CREATE SESSION TO NEW_USER")
    assert "PRIV_GRANT_OUTSIDE_WINDOW" not in rules(run([r]))


def test_any_privilege_counts_as_privileged():
    r = rec("2026-03-11 02:00:00", "DBA_ALICE", "GRANT", sql="GRANT SELECT ANY TABLE TO REPORTING")
    assert "PRIV_GRANT_OUTSIDE_WINDOW" in rules(run([r]))


def test_failed_grant_is_ignored():
    r = rec("2026-03-11 02:00:00", "X", "GRANT", rc=1031, sql="GRANT DBA TO X")
    assert "PRIV_GRANT_OUTSIDE_WINDOW" not in rules(run([r]))


def test_mass_select_flags_unusual_program_but_not_the_app():
    found = [f for f in run(sa.incident_records()) if f.rule == "MASS_SELECT"]
    assert len(found) == 1 and "SQL Developer" in found[0].detail and found[0].user == "APP_USER"


def test_mass_select_needs_threshold_and_sensitive_table():
    few = [rec(f"2026-03-11 03:00:{i:02d}", "X", "SELECT", obj="CARD_DATA") for i in range(10)]
    other = [rec(f"2026-03-11 03:00:{i:02d}", "X", "SELECT", obj="LOOKUP_COLORS") for i in range(40)]
    assert run(few) == [] and run(other) == []


def test_new_program_for_known_user_is_flagged():
    r = rec("2026-03-11 10:00:00", "APP_USER", "LOGON", host=sa.APP_HOST, program="SQL Developer")
    found = run([r])
    assert rules(found) == ["NEW_HOST_OR_PROGRAM"] and "new program" in found[0].detail


def test_new_host_flagged_and_alert_not_repeated():
    rs = [rec(f"2026-03-11 10:0{i}:00", "DBA_ALICE", "LOGON", host="198.51.100.9") for i in range(3)]
    assert rules(run(rs)) == ["NEW_HOST_OR_PROGRAM"]


def test_noaudit_and_drop_policy_are_critical():
    found = [f for f in run(sa.incident_records()) if f.rule == "AUDIT_TAMPERING"]
    assert len(found) == 2 and all(f.severity == "critical" for f in found)


def test_scheduled_audit_cleanup_is_only_medium():
    r = rec("2026-03-10 21:30:00", "DBA_ALICE", "EXECUTE", host=sa.DBA_HOST,
            sql="BEGIN DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(...); END;")
    f = run([r])
    assert [x.severity for x in f] == ["medium"]


def test_sys_failure_burst_then_success_is_critical():
    found = [f for f in run(sa.incident_records()) if f.rule == "ADMIN_LOGIN_BURST"]
    assert {f.severity for f in found} == {"high", "critical"}


def test_few_sys_failures_do_not_alert():
    rs = [rec(f"2026-03-11 03:00:{i * 10:02d}", "SYS", "LOGON", host="dbhost01.example",
              program="sqlplus@dbhost01.example (TNS V1-V3)", rc=1017) for i in range(3)]
    assert run(rs) == []


def test_failures_on_normal_user_are_not_admin_burst():
    rs = [rec(f"2026-03-11 03:00:{i * 5:02d}", "APP_USER", "LOGON", host=sa.APP_HOST,
              program=sa.APP_PROGRAM, rc=1017) for i in range(8)]
    assert "ADMIN_LOGIN_BURST" not in rules(run(rs))


def test_results_sorted_by_severity():
    order = [aa.SEVERITY_ORDER[f.severity] for f in run(sa.incident_records())]
    assert order == sorted(order, reverse=True)
