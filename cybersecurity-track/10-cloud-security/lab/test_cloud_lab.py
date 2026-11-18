"""Tests for the CloudTrail detector and the IAM policy analyzer.

Run from the repository root:
    .venv/Scripts/python -m pytest cybersecurity-track/10-cloud-security -v
"""

from pathlib import Path

from aisec_lab import load_lab_module

ct = load_lab_module(__file__, "cloudtrail_detector")
iam = load_lab_module(__file__, "iam_analyzer")
data = load_lab_module(__file__, "sample_data")

JSON_PATH = Path(__file__).with_name("sample_cloudtrail.json")


def rules(findings):
    return [f.rule for f in findings]


# ---------- CloudTrail detections ---------------------------------------------------

def test_json_file_loads_and_matches_builder():
    events = ct.load_events(JSON_PATH)
    assert len(events) == len(data.all_events())


def test_all_five_rules_fire_on_attack_day():
    found = set(rules(ct.detect(data.all_events())))
    assert found == {"ROOT_LOGIN", "KEY_NEW_COUNTRY", "LOGGING_DISABLED",
                     "BUCKET_MADE_PUBLIC", "CONSOLE_LOGIN_BURST"}


def test_benign_admin_activity_raises_nothing():
    # key rotation, MFA logins, two typos, a private bucket policy
    assert ct.detect(data.benign_events()) == []


def test_root_login_without_mfa_is_critical():
    f = [x for x in ct.detect(data.attack_events()) if x.rule == "ROOT_LOGIN"][0]
    assert f.severity == "critical" and "NOT used" in f.detail


def test_root_login_with_mfa_is_high():
    ev = data._login("10:00:00", None, "192.0.2.10", mfa=True, utype="Root")
    assert ct.detect([ev])[0].severity == "high"


def test_new_key_used_from_new_country_flagged_once_per_country():
    found = [x for x in ct.detect(data.all_events()) if x.rule == "KEY_NEW_COUNTRY"]
    assert len(found) == 1
    assert found[0].actor == "carol" and "RU" in found[0].detail


def test_new_key_used_from_usual_country_is_fine():
    # the svc-report key in the benign set is created and used from CA
    assert "KEY_NEW_COUNTRY" not in rules(ct.detect(data.benign_events()))


def test_stoplogging_and_deletetrail_both_flagged():
    found = [x for x in ct.detect(data.attack_events()) if x.rule == "LOGGING_DISABLED"]
    assert {"StopLogging", "DeleteTrail"} == {w for f in found for w in ("StopLogging", "DeleteTrail") if w in f.detail}


def test_failed_stoplogging_is_not_flagged():
    ev = data._ev("12:00:00", "StopLogging", "carol", request={"name": "t"}, error="AccessDenied")
    assert ct.detect([ev]) == []


def test_public_bucket_policy_flagged_but_condition_makes_it_ok():
    public = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "x"}]}
    cond = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "x",
                           "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-0example"}}}]}
    assert ct.policy_is_public(public)
    assert not ct.policy_is_public(cond)


def test_burst_needs_threshold_and_window():
    few = [data._login(f"03:0{i}:00", "zed", "203.0.113.5", ok=False) for i in range(4)]
    assert ct.detect(few) == []
    slow = [data._login(f"0{i}:00:00", "zed", "203.0.113.5", ok=False) for i in range(1, 8)]
    assert ct.detect(slow) == []  # one failure per hour is not a burst


def test_success_after_burst_is_critical():
    found = [x for x in ct.detect(data.attack_events()) if x.rule == "CONSOLE_LOGIN_BURST"]
    assert {"medium", "critical"} == {f.severity for f in found}


def test_findings_sorted_most_severe_first():
    sev = [ct.SEVERITY_ORDER[f.severity] for f in ct.detect(data.all_events())]
    assert sev == sorted(sev, reverse=True)


# ---------- IAM analyzer ------------------------------------------------------------

def analyze(name):
    return iam.analyze_policy(data.SAMPLE_POLICIES[name], name)


def test_admin_star_star_is_critical():
    assert "ADMIN_EQUIVALENT" in rules(analyze("AdministratorAccess-like"))


def test_passrole_with_run_instances_is_escalation():
    found = rules(analyze("DevOpsPassRole"))
    assert "PASSROLE_WILDCARD" in found and "PASSROLE_ESCALATION" in found


def test_passrole_on_one_role_is_not_wildcard():
    policy = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole",
                             "Resource": "arn:aws:iam::111122223333:role/app-runtime"}]}
    assert "PASSROLE_WILDCARD" not in rules(iam.analyze_policy(policy))


def test_missing_mfa_flagged_and_condition_fixes_it():
    assert "NO_MFA_CONDITION" in rules(analyze("IamManagerNoMfa"))
    assert "NO_MFA_CONDITION" not in rules(analyze("IamManagerWithMfa"))


def test_deny_without_mfa_guard_counts_as_mfa_control():
    assert "NO_MFA_CONDITION" not in rules(analyze("AdminWithMfaGuard"))


def test_least_privilege_and_readonly_policies_are_clean():
    assert analyze("S3AppLeastPrivilege") == []
    assert analyze("ReadOnlyAuditor") == []


def test_notaction_allow_flagged():
    assert "NOT_ACTION_ALLOW" in rules(analyze("NotActionTrap"))


def test_service_wildcard_is_medium_but_iam_wildcard_is_high():
    s3 = iam.analyze_policy({"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b"}})
    iam_wild = iam.analyze_policy({"Statement": {"Effect": "Allow", "Action": "iam:*", "Resource": "arn:aws:iam::1:user/x"}})
    assert s3[0].severity == "medium"
    assert "high" in [f.severity for f in iam_wild]


def test_privesc_action_on_wildcard_resource():
    p = {"Statement": [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]}
    assert "PRIVESC_ACTION" in rules(iam.analyze_policy(p))


def test_deny_statements_never_produce_findings():
    p = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    assert iam.analyze_policy(p) == []


def test_analyze_many_sorts_critical_first():
    found = iam.analyze_many(data.SAMPLE_POLICIES)
    assert found[0].severity == "critical"
