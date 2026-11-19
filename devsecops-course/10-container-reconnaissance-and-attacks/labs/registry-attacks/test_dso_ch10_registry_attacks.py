from aisec_lab import load_lab_module

ra = load_lab_module(__file__, "regattack")


def run(mode, token):
    return ra.attack(ra.seed(ra.Registry(mode)), token)


def test_open_registry_everything_works():
    r = run("open", None)
    assert r["enumerate catalog"][0] == 200
    assert r["secrets in configs"] == ["shop/api:1.0 DB_PASSWORD"]
    assert r["overwrite shop/web:1.0"] == 201 and r["delete shop/api:1.0"] == 202


def test_authentication_without_rbac_lets_a_reader_push_and_delete():
    r = run("auth-no-rbac", "tok-bob")
    assert r["overwrite shop/web:1.0"] == 201 and r["delete shop/api:1.0"] == 202
    assert r["secrets in configs"]


def test_no_token_on_authenticated_registry_is_401():
    reg = ra.seed(ra.Registry("auth-no-rbac"))
    assert reg.catalog(None)[0] == 401
    r = ra.attack(reg, None)
    assert r["overwrite shop/web:1.0"] == 401 and r["secrets in configs"] == []


def test_rbac_reader_cannot_push_delete_or_list_catalog():
    r = run("rbac", "tok-bob")
    assert r["enumerate catalog"][0] == 403
    assert r["overwrite shop/web:1.0"] == 403 and r["delete shop/api:1.0"] == 403


def test_rbac_reader_still_reads_its_own_scope_but_not_other_teams():
    reg = ra.seed(ra.Registry("rbac"))
    assert reg.tags("shop/web", "tok-bob")[0] == 200
    assert reg.pull("hr/payroll", "5", "tok-bob")[0] == 403


def test_immutable_tags_stop_even_the_ci_token():
    r = run("rbac", "tok-alice")
    assert r["overwrite shop/web:1.0"] == 409
    assert r["delete shop/api:1.0"] == 403


def test_ci_can_push_a_new_tag_under_rbac():
    reg = ra.seed(ra.Registry("rbac"))
    assert reg.push("shop/web", "1.1", {"layers": []}, "tok-alice")[0] == 201
    assert reg.push("hr/payroll", "6", {"layers": []}, "tok-alice")[0] == 403


def test_overwrite_changes_digest_in_open_mode():
    reg = ra.seed(ra.Registry("open"))
    before = ra.digest(reg.repos["shop/web"]["1.0"])
    ra.attack(reg, None)
    assert ra.digest(reg.repos["shop/web"]["1.0"]) != before
