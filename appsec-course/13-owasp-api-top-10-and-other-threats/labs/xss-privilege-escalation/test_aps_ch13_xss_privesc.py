from aisec_lab import load_lab_module

x = load_lab_module(__file__, "xss_privesc")


def test_stored_xss_steals_admin_cookie_and_promotes_attacker_with_no_defences():
    assert x.run_attack() == {"mallory_role": "admin", "cookie_stolen": True}


def test_httponly_stops_cookie_theft_but_not_same_origin_privilege_escalation():
    assert x.run_attack(httponly=True) == {"mallory_role": "admin", "cookie_stolen": False}


def test_csrf_token_stops_the_action_but_not_cookie_theft():
    assert x.run_attack(csrf=True) == {"mallory_role": "user", "cookie_stolen": True}


def test_strict_csp_blocks_injected_script_entirely():
    assert x.run_attack(csp=True) == {"mallory_role": "user", "cookie_stolen": False}


def test_output_encoding_removes_the_injection():
    assert x.run_attack(encode=True) == {"mallory_role": "user", "cookie_stolen": False}


def test_legit_nonced_script_still_runs_under_csp():
    app = x.App(csp=True)
    assert x.SimBrowser(app, app.login("admin")).visit_moderation() == ["ui.init()"]


def test_admin_api_rejects_non_admin_sessions():
    app = x.App()
    assert app.api("POST", "/api/admin/users/mallory/role", "admin", app.login("mallory")) == 403
