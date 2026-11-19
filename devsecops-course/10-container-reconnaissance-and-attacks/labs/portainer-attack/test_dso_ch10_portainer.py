from aisec_lab import load_lab_module

ps = load_lab_module(__file__, "portainer_sim")


def test_first_run_takeover_only_when_uninitialised_and_exposed():
    ui = ps.vulnerable()
    assert ui.first_run_takeover("x-canary") is True
    assert ui.login("admin", "x-canary")
    assert ps.default_creds().first_run_takeover("y") is False       # already has an admin
    assert ps.ManagementUI(ps.Environment(), exposed=False, admin_set=False).first_run_takeover("z") is False


def test_default_credentials_work_and_are_flagged():
    ui = ps.default_creds()
    assert ui.login("admin", "admin")
    assert ("CRITICAL", "default/weak admin password") in ui.exposure_findings()


def test_blast_radius_lists_secrets_and_host_root():
    br = ps.vulnerable().blast_radius()
    assert br["containers_controllable"] == 4 and br["host_root_equivalent"] is True
    assert ("shop-api", "DB_PASSWORD") in br["secrets_visible_in_env"]
    assert ("ci-runner", "RUNNER_TOKEN") in br["secrets_visible_in_env"]
    assert br["other_hosts_via_agents"] == 3


def test_hardened_has_no_findings_and_no_host_root():
    ui = ps.hardened()
    assert ui.exposure_findings() == []
    assert ui.blast_radius()["host_root_equivalent"] is False


def test_mfa_blocks_password_only_login():
    ui = ps.hardened()
    assert ui.login("admin", "long-random-canary-pw-7f3a9c") is False
    assert ui.login("admin", "long-random-canary-pw-7f3a9c", "000000-canary") is True


def test_failed_logins_counted():
    ui = ps.default_creds()
    ui.login("admin", "wrong"); ui.login("admin", "wrong2")
    assert ui.failed_logins == 2


def test_rbac_alone_removes_root_equivalence_claim():
    ui = ps.ManagementUI(ps.Environment(), exposed=False, admin_set=True, rbac=True)
    assert ui.blast_radius()["host_root_equivalent"] is False


def test_hardening_list_covers_key_controls():
    text = " ".join(ps.HARDENING).lower()
    for word in ("vpn", "tls", "mfa", "role-based", "socket proxy", "admin account"):
        assert word in text
