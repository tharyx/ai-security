from pathlib import Path

from aisec_lab import load_lab_module

ap = load_lab_module(__file__, "applier")
HERE = Path(__file__).parent
ROLE = HERE / "fixtures" / "role"
WEAK = HERE / "fixtures" / "host_weak.json"


def failed(state):
    return {r["id"] for r in ap.run_checks(state) if r["status"] == "fail"}


def test_weak_host_fails_many_checks():
    state = ap.load_state(WEAK)
    bad = failed(state)
    assert {"CIS-SSH-01", "CIS-PKG-01", "CIS-USR-02", "CIS-SYS-01", "CIS-FS-01"} <= bad
    assert ap.score(ap.run_checks(state)) < 30


def test_role_brings_host_to_full_compliance():
    state = ap.load_state(WEAK)
    report = ap.apply_role(state, ROLE)
    assert report.changed > 10
    assert failed(state) == set()
    assert ap.score(ap.run_checks(state)) == 100.0


def test_role_is_idempotent():
    state = ap.load_state(WEAK)
    ap.apply_role(state, ROLE)
    again = ap.apply_role(state, ROLE)
    assert again.changed == 0


def test_drift_is_corrected_and_only_the_drift():
    state = ap.load_state(WEAK)
    ap.apply_role(state, ROLE)
    state["sysctl"]["net.ipv4.ip_forward"] = "1"
    report = ap.apply_role(state, ROLE)
    assert report.changed == 1 and "ip_forward" in report.changes[0]
    assert failed(state) == set()


def test_lineinfile_replaces_last_match_and_first_uncommented_wins():
    state = ap.load_state(WEAK)
    ap.apply_role(state, ROLE)
    assert ap.sshd_value(state, "PermitRootLogin") == "no"
    content = state["files"]["/etc/ssh/sshd_config"]["content"]
    assert "PermitRootLogin yes" not in content


def test_overrides_change_the_result():
    state = ap.load_state(WEAK)
    ap.apply_role(state, ROLE, overrides={"sshd_settings": [{"key": "MaxAuthTries", "value": "9"}]})
    assert "CIS-SSH-03" in failed(state)


def test_uid0_duplicate_removed_and_service_accounts_nologin():
    state = ap.load_state(WEAK)
    ap.apply_role(state, ROLE)
    assert "toor" not in state["users"] and "guest" not in state["users"]
    assert state["users"]["appsvc"]["shell"].endswith("nologin")


def test_mode_ok_logic():
    assert ap.mode_ok("0640", "0640") and ap.mode_ok("0600", "0640") and not ap.mode_ok("0644", "0640")


def test_missing_state_keys_fail_closed():
    assert "CIS-AUD-01" in failed({})


def test_renderer_join_and_dotted_lookup():
    ctx = {"rules": ["a", "b"], "item": {"key": "K", "value": "V"}}
    assert ap.render("{{ rules | join('\n') }}", ctx) == "a\nb"
    assert ap.render("{{ item.key }} {{ item.value }}", ctx) == "K V"
