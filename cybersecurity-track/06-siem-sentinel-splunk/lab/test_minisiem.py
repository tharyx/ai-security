"""Tests for the mini SIEM: parsers, YAML rules (true positives and benign negatives), checker.

Run from the repository root:
    python -m pytest cybersecurity-track/06-siem-sentinel-splunk -v
"""

import importlib.util
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

siem = load_lab_module(__file__, "minisiem")
CHECKER_PATH = Path(__file__).resolve().parent / "queries" / "check_answers.py"

T0 = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)
RULES = {r["id"]: r for r in siem.load_rules()}
BRUTE, SPRAY, TRAVEL, ADMIN, ENC, RARE = (f"cyb06-000{i}" for i in range(1, 7))


def ev(minutes=0, **kw):
    kw.setdefault("source", "windows")
    kw.setdefault("action", "logon_failure")
    return siem.Event(id=f"t-{len(kw)}-{minutes}-{kw.get('user', '')}{kw.get('src_ip', '')}", ts=T0 + timedelta(minutes=minutes), **kw)


def fire(rule_id, events):
    return siem.run_rule(RULES[rule_id], events)


# ---------- parsers and normalization ------------------------------------------------

def test_windows_4625_is_normalized_to_logon_failure():
    line = '{"TimeCreated": "2026-11-10T02:10:00Z", "EventID": 4625, "Computer": "RDP-SRV-01", "TargetUserName": "admin01", "IpAddress": "203.0.113.50", "LogonType": 10}'
    (e,) = siem.parse_windows([line])
    assert (e.source, e.action, e.user, e.src_ip, e.host) == ("windows", "logon_failure", "admin01", "203.0.113.50", "RDP-SRV-01")


def test_entra_error_code_maps_to_action_and_upn_is_shortened():
    ok = '{"createdDateTime": "2026-11-10T08:00:00Z", "userPrincipalName": "alice@corp.example", "ipAddress": "192.0.2.11", "location": "US", "appDisplayName": "x", "status": {"errorCode": 0}}'
    bad = ok.replace('"errorCode": 0', '"errorCode": 50126')
    a, b = siem.parse_entra([ok, bad])
    assert (a.action, a.user, a.country) == ("logon_success", "alice", "US")
    assert b.action == "logon_failure"


def test_linux_ssh_lines_parse_and_other_lines_are_skipped():
    lines = ["Nov 10 03:00:00 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2",
             "Nov 10 03:00:01 web01 sshd[2]: Accepted publickey for deploy from 192.0.2.50 port 22 ssh2: RSA SHA256:x",
             "Nov 10 03:00:02 web01 CRON[3]: pam_unix(cron:session): session opened for user root"]
    events = siem.parse_linux(lines)
    assert [e.action for e in events] == ["logon_failure", "logon_success"]
    assert events[0].user == "admin" and events[0].ts.year == 2026


def test_firewall_csv_parses_ports_and_bytes():
    text = "time,src_ip,dst_ip,dst_port,proto,action,bytes_out\n2026-11-10T14:45:00Z,192.0.2.77,203.0.113.80,4444,tcp,allow,300000000\n"
    (e,) = siem.parse_firewall(text)
    assert (e.action, e.dst_port, e.bytes_out) == ("network_allow", 4444, 300_000_000)


def test_ingest_reads_all_four_sources():
    events = siem.ingest()
    assert {e.source for e in events} == {"windows", "entra", "firewall", "linux"}
    assert events == sorted(events, key=lambda e: (e.ts, e.id))
    assert all(e.ts.tzinfo is not None for e in events)


# ---------- rule file hygiene ----------------------------------------------------------

def test_six_rules_with_unique_ids_and_attack_tags():
    assert len(RULES) == 6
    for r in RULES.values():
        assert any(t.startswith("attack.t") for t in r["tags"]), r["id"]
        assert r["level"] in ("low", "medium", "high", "critical")
        assert r.get("falsepositives"), f"{r['id']} should document false positives"


def test_invalid_condition_is_rejected():
    bad = yaml.safe_load("title: x\nid: y\nlevel: low\ntags: []\ndetection:\n  selection: {action: a}\n  condition: selection and typo\n")
    with pytest.raises(ValueError):
        siem.validate_rule(bad)


def test_condition_parser_precedence_and_parentheses():
    det = {"a": {"x": 1}, "b": {"y": 1}, "c": {"z": 1}}
    e = {"x": 1, "y": 0, "z": 0}
    assert siem._eval_condition("a and not b", det, e)
    assert not siem._eval_condition("a and b", det, e)
    assert siem._eval_condition("b or a and not c", det, e)
    assert not siem._eval_condition("(b or c) and a", det, e)


# ---------- brute force ------------------------------------------------------------------

def test_brute_force_fires_on_12_failures_in_4_minutes():
    events = [ev(k * 0.3, user="admin01", src_ip="203.0.113.50") for k in range(12)]
    (a,) = fire(BRUTE, events)
    assert a.entity == {"src_ip": "203.0.113.50", "user": "admin01"} and a.count == 12


def test_brute_force_ignores_three_typos():
    assert fire(BRUTE, [ev(k, user="bob", src_ip="192.0.2.30") for k in range(3)]) == []


def test_brute_force_ignores_failures_spread_over_hours():
    assert fire(BRUTE, [ev(k * 30, user="svc-backup", src_ip="192.0.2.60") for k in range(10)]) == []


def test_brute_force_counts_per_user_not_per_ip():
    # 12 failures from one IP, but 12 different users: that is spraying, not brute force
    assert fire(BRUTE, [ev(k * 0.2, user=f"u{k}", src_ip="203.0.113.9") for k in range(12)]) == []


def test_brute_force_does_not_apply_to_entra_source():
    events = [ev(k * 0.3, source="entra", user="admin01", src_ip="203.0.113.50") for k in range(12)]
    assert fire(BRUTE, events) == []


# ---------- password spray ------------------------------------------------------------------

def test_spray_fires_on_ten_accounts_from_one_ip():
    events = [ev(k * 0.5, source="entra", user=f"u{k}", src_ip="198.51.100.66") for k in range(10)]
    (a,) = fire(SPRAY, events)
    assert a.entity == {"src_ip": "198.51.100.66"} and a.attack == ["T1110.003"]


def test_spray_ignores_shared_nat_with_three_users():
    events = [ev(k, source="entra", user=f"u{k}", src_ip="192.0.2.40") for k in range(3)]
    assert fire(SPRAY, events) == []


def test_spray_ignores_slow_attempts_outside_the_window():
    events = [ev(k * 20, source="entra", user=f"u{k}", src_ip="198.51.100.66") for k in range(10)]
    assert fire(SPRAY, events) == []


def test_spray_ignores_successful_sign_ins():
    events = [ev(k * 0.5, source="entra", action="logon_success", user=f"u{k}", src_ip="192.0.2.40") for k in range(10)]
    assert fire(SPRAY, events) == []


# ---------- impossible travel --------------------------------------------------------------------

def test_impossible_travel_fires_us_then_ro_in_30_minutes():
    events = [ev(0, source="entra", action="logon_success", user="alice", country="US"),
              ev(30, source="entra", action="logon_success", user="alice", country="RO")]
    (a,) = fire(TRAVEL, events)
    assert a.entity == {"user": "alice"}


def test_impossible_travel_ignores_same_country():
    events = [ev(0, source="entra", action="logon_success", user="bob", country="US"),
              ev(10, source="entra", action="logon_success", user="bob", country="US")]
    assert fire(TRAVEL, events) == []


def test_impossible_travel_ignores_a_flight_length_gap():
    events = [ev(0, source="entra", action="logon_success", user="dave", country="US"),
              ev(720, source="entra", action="logon_success", user="dave", country="JP")]
    assert fire(TRAVEL, events) == []


def test_impossible_travel_ignores_failed_sign_ins_from_other_countries():
    events = [ev(0, source="entra", action="logon_success", user="erin", country="US"),
              ev(5, source="entra", action="logon_failure", user="erin", country="NL")]
    assert fire(TRAVEL, events) == []


def test_impossible_travel_tracks_users_separately():
    events = [ev(0, source="entra", action="logon_success", user="a", country="US"),
              ev(5, source="entra", action="logon_success", user="b", country="FR")]
    assert fire(TRAVEL, events) == []


# ---------- new admin group member ----------------------------------------------------------------

def test_new_domain_admin_fires():
    (a,) = fire(ADMIN, [ev(source="windows", action="group_add", user="helpdesk1", host="DC-01", group="Domain Admins", member="tmp")])
    assert a.attack == ["T1098"]


def test_group_name_match_is_case_insensitive():
    assert len(fire(ADMIN, [ev(action="group_add", user="x", group="domain admins", member="m")])) == 1


def test_ordinary_group_change_is_ignored():
    assert fire(ADMIN, [ev(action="group_add", user="helpdesk1", group="Marketing-Share", member="carol")]) == []


def test_approved_provisioning_account_is_filtered():
    assert fire(ADMIN, [ev(action="group_add", user="svc-provisioning", group="Administrators", member="svc-deploy2")]) == []


def test_filter_is_exact_not_a_prefix():
    assert len(fire(ADMIN, [ev(action="group_add", user="svc-provisioning-evil", group="Administrators", member="m")])) == 1


# ---------- encoded powershell -----------------------------------------------------------------------

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def test_encoded_powershell_fires_for_encodedcommand_and_enc():
    for flag in ("-EncodedCommand", "-enc"):
        e = ev(action="process_create", process=PS, parent_process="WINWORD.EXE", command_line=f"powershell.exe -NoProfile {flag} VwByAGkA")
        assert len(fire(ENC, [e])) == 1, flag


def test_powershell_with_script_file_is_ignored():
    e = ev(action="process_create", process=PS, command_line="powershell.exe -ExecutionPolicy Bypass -File backup.ps1")
    assert fire(ENC, [e]) == []


def test_sccm_parent_is_filtered_out():
    e = ev(action="process_create", process=PS, parent_process="C:\\Windows\\CCM\\CcmExec.exe", command_line="powershell.exe -enc VwBy")
    assert fire(ENC, [e]) == []


def test_enc_text_in_another_program_is_ignored():
    e = ev(action="process_create", process="C:\\tools\\gpg.exe", command_line="gpg.exe -enc file.txt ")
    assert fire(ENC, [e]) == []


# ---------- rare outbound port --------------------------------------------------------------------------

def test_rare_port_fires_once_per_host_and_port():
    events = [ev(k, source="firewall", action="network_allow", src_ip="192.0.2.77", dst_ip="203.0.113.80", dst_port=4444) for k in range(3)]
    (a,) = fire(RARE, events)
    assert a.count == 3 and a.entity["dst_port"] == 4444


@pytest.mark.parametrize("port", [53, 80, 123, 443, 8080, 8443])
def test_common_ports_do_not_fire(port):
    assert fire(RARE, [ev(source="firewall", action="network_allow", src_ip="192.0.2.25", dst_port=port)]) == []


def test_denied_traffic_on_rare_port_is_ignored():
    assert fire(RARE, [ev(source="firewall", action="network_deny", src_ip="203.0.113.50", dst_port=3389)]) == []


# ---------- full pipeline on the sample data ----------------------------------------------------------------

def test_sample_data_produces_exactly_the_planted_alerts():
    alerts = siem.run_all(siem.load_rules(), siem.ingest())
    got = sorted((a.rule_id, tuple(sorted(a.entity.items()))) for a in alerts)
    want = sorted([
        (BRUTE, (("src_ip", "203.0.113.50"), ("user", "admin01"))),
        (BRUTE, (("src_ip", "203.0.113.77"), ("user", "root"))),
        (SPRAY, (("src_ip", "198.51.100.66"),)),
        (TRAVEL, (("user", "alice"),)),
        (ADMIN, (("host", "DC-01"), ("user", "helpdesk1"))),
        (ENC, (("host", "HR-WS-12"), ("user", "erin"))),
        (RARE, (("dst_port", 4444), ("src_ip", "192.0.2.77"))),
    ])
    assert got == want


def test_sample_data_benign_noise_raises_no_alert():
    alerts = siem.run_all(siem.load_rules(), siem.ingest())
    text = " ".join(str(a.entity) for a in alerts)
    for benign in ("svc-backup", "192.0.2.30", "192.0.2.40", "dave", "192.0.2.25", "svc-provisioning", "FIN-WS-07"):
        assert benign not in text


def test_exports_have_every_event():
    events = siem.ingest()
    kql = siem.export_kql_datatable(events)
    assert kql.startswith("let Events = datatable(") and kql.count("datetime(") == len(events)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "e.csv"
        siem.export_csv(events, p)
        lines = p.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(events) + 1 and lines[0].startswith("ts,log_source,action,hostname")


# ---------- query answer checker ------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def checker():
    spec = importlib.util.spec_from_file_location("check_answers_under_test", CHECKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_expected_answers_match_the_planted_story(checker):
    exp = checker.expected_answers(siem.ingest())
    assert exp["Q1"] == 25 and exp["Q2"] == "203.0.113.50" and exp["Q3"] == 10
    assert exp["Q4"] == "alice" and exp["Q5"] == "tmp-contractor"
    assert exp["Q6"] == 2 and exp["Q7"] == "HR-WS-12" and exp["Q8"] == 4444
    assert exp["Q9"] == 1350 and exp["Q10"] == 2 and exp["Q11"] == 2 and exp["Q12"] == "bob"


def test_checker_accepts_correct_answers_in_any_case_or_type(checker):
    exp = checker.expected_answers(siem.ingest())
    answers = {q: str(v).upper() for q, v in exp.items()}
    assert all(checker.check(answers, exp).values())


def test_checker_flags_wrong_and_missing_answers(checker):
    exp = checker.expected_answers(siem.ingest())
    res = checker.check({"Q1": 24, "Q2": "203.0.113.50"}, exp)
    assert res["Q1"] is False and res["Q2"] is True and res["Q3"] is None


def test_every_question_has_a_kql_and_spl_solution(checker):
    folder = CHECKER_PATH.parent
    kql = (folder / "solutions.kql").read_text(encoding="utf-8")
    spl = (folder / "solutions.spl").read_text(encoding="utf-8")
    for q in checker.QUESTIONS:
        assert f"// {q}" in kql and f"# {q}" in spl, q
