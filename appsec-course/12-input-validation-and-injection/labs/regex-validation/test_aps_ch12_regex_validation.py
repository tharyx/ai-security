from aisec_lab import load_lab_module

v = load_lab_module(__file__, "validators")


def test_re_match_without_end_anchor_accepts_injection_suffix():
    assert v.weak_match("alice; DROP TABLE users") is True
    assert v.validate(v.USERNAME, "alice; DROP TABLE users") is False


def test_dollar_anchor_accepts_trailing_newline_but_fullmatch_does_not():
    assert v.weak_dollar("alice\n") is True
    assert v.validate(v.USERNAME, "alice\n") is False


def test_denylist_is_bypassed_by_case_and_other_tags_allowlist_is_not():
    for payload in ("<ScRiPt>x</ScRiPt>", "<img src=x onerror=alert(1)>"):
        assert v.denylist_filter(payload) is True
        assert v.allowlist_comment(payload) is False
    assert v.allowlist_comment("Nice post, thanks!")


def test_validators_accept_good_and_reject_bad_values():
    assert v.validate(v.POSTCODE_IN, "560001") and not v.validate(v.POSTCODE_IN, "056001")
    assert v.validate(v.ISO_DATE, "2026-11-19") and not v.validate(v.ISO_DATE, "2026-13-01")
    assert v.validate(v.EMAIL_SIMPLE, "a.b@lab.example") and not v.validate(v.EMAIL_SIMPLE, "a@b")
    assert not v.validate(v.USERNAME, 12345)


def test_length_cap_rejects_before_regex_runs():
    assert v.validate(v.USERNAME, "a" * 10_000) is False


def test_redos_heuristic_flags_nested_quantifiers_only():
    assert v.looks_redos_prone(r"^(a+)+$") and v.looks_redos_prone(r"^(\w*)*@")
    assert not v.looks_redos_prone(r"^a+$") and not v.looks_redos_prone(r"[a-z0-9_]{3,20}")


def test_skipping_client_side_check_works_unless_server_validates():
    evil = "x' OR 1=1 --"
    assert v.client_side_form_check(evil) is False
    assert v.server_create_user(evil, validate_on_server=False)[0] == 201
    assert v.server_create_user(evil, validate_on_server=True)[0] == 422


def test_sanitizer_normalizes_and_strips_control_and_bidi_characters():
    assert v.sanitize_display_name("  Ａlice‮  \t Smith\x00 ") == "Alice Smith"
