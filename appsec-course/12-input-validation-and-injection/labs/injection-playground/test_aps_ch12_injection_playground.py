import pytest

from aisec_lab import load_lab_module

L = load_lab_module(__file__, "injection_lab")


def test_sqli_tautology_reveals_hidden_product_only_when_vulnerable():
    c = L.make_db()
    assert ("unreleased-phone", 99999.0) in L.search_vuln(c, "' OR hidden = 1 --")
    assert L.search_safe(c, "' OR hidden = 1 --") == []


def test_sqli_union_dumps_admin_password_only_when_vulnerable():
    c = L.make_db()
    rows = L.search_vuln(c, "' UNION SELECT name, password FROM users --")
    assert ("admin", L.ADMIN_PW) in rows
    assert L.search_safe(c, "' UNION SELECT name, password FROM users --") == []


def test_bind_variables_still_find_normal_results():
    assert L.search_safe(L.make_db(), "bo") == [("book", 250.0)]


def test_orm_order_by_injection_extracts_password_via_sort_oracle():
    orm = L.MiniORM(L.make_db(), secure=False)
    assert L.orm_extract_password(orm, len(L.ADMIN_PW)) == L.ADMIN_PW


def test_secure_orm_rejects_expressions_but_allows_valid_sort():
    orm = L.MiniORM(L.make_db(), secure=True)
    assert orm.products(order_by="-price") == ["lamp", "book", "pen"]
    with pytest.raises(ValueError):
        orm.products(order_by="(CASE WHEN 1=1 THEN price END)")


def test_nosql_ne_operator_bypasses_login_only_when_vulnerable():
    attack = {"username": "admin", "password": {"$ne": ""}}
    assert L.nosql_login_vuln(attack)["role"] == "admin"
    with pytest.raises(ValueError):
        L.nosql_login_safe(attack)
    assert L.nosql_login_safe({"username": "alice", "password": "FAKE-alice-pw"})["role"] == "user"


def test_nosql_regex_operator_enumerates_users():
    assert L.nosql_login_vuln({"username": {"$regex": "^a"}, "password": {"$ne": None}}) is not None


def test_ssrf_reads_fake_cloud_metadata_only_when_vulnerable():
    assert L.METADATA_CANARY in L.preview_vuln("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError):
        L.preview_safe("http://169.254.169.254/latest/meta-data/")


def test_ssrf_dns_and_decimal_ip_tricks_blocked_by_secure_preview():
    assert L.METADATA_CANARY in L.preview_vuln("http://2852039166/")
    for url in ("http://2852039166/", "https://metadata.attacker.example/", "https://internal-admin.corp/"):
        with pytest.raises(ValueError):
            L.preview_safe(url)
    assert L.preview_safe("https://images.partner.example/cat.png") == "<img data>"
