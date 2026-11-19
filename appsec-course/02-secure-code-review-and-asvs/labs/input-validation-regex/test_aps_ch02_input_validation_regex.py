import pytest

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "validators")


def test_re_match_accepts_sql_payload_after_a_valid_prefix_but_fullmatch_rejects():
    payload = "bob'; DROP TABLE users--"
    assert v.weak_username(payload) is True
    assert v.strong_username(payload) is False


def test_dollar_anchor_lets_a_trailing_newline_through():
    assert v.weak_username_dollar("alice\n") is True
    assert v.strong_username("alice\n") is False


def test_fullwidth_unicode_is_normalized_before_reserved_name_check():
    fullwidth_admin = "ａｄｍｉｎ"
    assert v.normalize(fullwidth_admin) == "admin"
    assert v.strong_username(fullwidth_admin) is False


def test_blocklist_misses_img_onerror():
    assert v.weak_comment_blocklist("<img src=x onerror=alert(1)>") is True


def test_search_finds_digits_inside_junk_but_fullmatch_does_not():
    assert v.weak_pin("411001 OR 1=1") is True
    assert v.strong_pin("411001 OR 1=1") is False


@pytest.mark.parametrize("fn,good,bad", [
    (v.strong_pin, "411001", "011001"),
    (v.strong_phone, "+919812345678", "09812345678"),
    (v.strong_email, "alice@shop.example", "alice@@shop.example"),
    (v.strong_quantity, "3", "11"),
    (v.strong_username, "alice_01", "Al"),
])
def test_strong_validators_accept_good_and_reject_bad(fn, good, bad):
    assert fn(good) is True and fn(bad) is False


def test_quantity_rejects_non_ascii_digits():
    assert v.strong_quantity("٣") is False  # Arabic-Indic digit three: isdigit() is True


def test_regex_alone_accepts_impossible_date_but_strong_date_does_not():
    assert v.ISO_DATE.fullmatch("2026-02-30")
    assert v.strong_date("2026-02-30") is False and v.strong_date("2028-02-29") is True


def test_schema_rejects_unknown_role_field_mass_assignment():
    clean, errors = v.validate_form({"username": "alice", "email": "alice@shop.example", "pin": "411001",
                                     "quantity": "2", "role": "admin"})
    assert clean == {} and "unknown field: role" in errors


def test_schema_accepts_valid_form():
    clean, errors = v.validate_form({"username": "alice", "email": "alice@shop.example", "pin": "411001",
                                     "quantity": "2"})
    assert errors == [] and clean["username"] == "alice"


@pytest.mark.parametrize("pattern,nested", [
    (r"(a+)+$", True), (r"(\w+\s?)*$", True), (r"([a-z0-9]+)*@", True),
    (r"[a-z]+$", False), (r"[A-Z]{3}-[0-9]{4}", False), (r"(ab)+", False),
])
def test_redos_heuristic_flags_nested_quantifiers(pattern, nested):
    assert v.has_nested_quantifier(pattern) is nested
