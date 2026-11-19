import pytest

from aisec_lab import load_lab_module

repo = load_lab_module(__file__, "repo")
UNION = "zz' UNION SELECT username, password_hash FROM users--"


@pytest.fixture()
def db():
    d = repo.make_db()
    yield d
    d.close()


def test_union_payload_leaks_users_on_vuln_search(db):
    assert "admin" in [r[0] for r in repo.search_vuln(db, UNION)]


def test_union_payload_is_just_text_on_fixed_search(db):
    assert repo.search_fixed(db, UNION) == []
    assert repo.search_fixed(db, "jam") == [("Cherry jam", 4.0)]


def test_quote_in_normal_input_breaks_vuln_but_not_fixed(db):
    with pytest.raises(Exception):
        repo.search_vuln(db, "O'Reilly")
    assert repo.search_fixed(db, "O'Reilly") == []


def test_comment_payload_logs_in_as_admin_on_vuln_login(db):
    assert repo.login_vuln(db, "admin'--", "wrong") == (2, "admin")


def test_fixed_login_rejects_payload_and_accepts_real_password(db):
    assert repo.login_fixed(db, "admin'--", "wrong") is None
    assert repo.login_fixed(db, "alice", "alice-lab-pw") == (1, "customer")
    assert repo.login_fixed(db, "alice", "wrong") is None


def test_order_by_injection_is_a_boolean_oracle_on_vuln(db):
    yes = repo.order_by_oracle(repo.list_sorted_vuln, db, "1=1")
    no = repo.order_by_oracle(repo.list_sorted_vuln, db, "1=0")
    assert yes != no  # different order = one bit of hidden data per request


def test_fixed_sort_allowlist_rejects_expressions_and_keeps_features(db):
    with pytest.raises(ValueError):
        repo.order_by_oracle(repo.list_sorted_fixed, db, "1=1")
    assert repo.list_sorted_fixed(db, "-price") == ["Banana bread", "Cherry jam", "Apple juice"]


def test_in_list_injection_reveals_hidden_rows_on_vuln(db):
    assert "Staff-only sample" in repo.by_ids_vuln(db, "1) OR (1=1")


def test_fixed_in_list_binds_each_id(db):
    with pytest.raises(ValueError):
        repo.by_ids_fixed(db, "1) OR (1=1")
    assert repo.by_ids_fixed(db, "1,3") == ["Apple juice", "Cherry jam"]
    assert repo.by_ids_fixed(db, "4") == []  # hidden rows stay hidden
