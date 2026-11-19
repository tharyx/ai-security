from aisec_lab import load_lab_module

s = load_lab_module(__file__, "mini_sqlmap")


def test_detects_boolean_and_time_based_injection_on_vulnerable_target():
    assert s.detect(s.Target(secure=False)) == {"boolean_blind": True, "time_based": True}


def test_extracts_fake_secret_through_boolean_oracle():
    assert s.extract(s.Target(False), "SELECT value FROM secrets WHERE id=1") == s.SECRET


def test_bisection_needs_about_seven_requests_per_character():
    s.extract(s.Target(False), "SELECT value FROM secrets WHERE id=1")
    assert s.extract.requests <= 7 * (len(s.SECRET) + 1)


def test_parameterized_target_is_not_injectable():
    assert s.detect(s.Target(secure=True)) == {"boolean_blind": False, "time_based": False}


def test_parameterized_target_extracts_nothing():
    assert s.extract(s.Target(True), "SELECT value FROM secrets WHERE id=1") == ""


def test_normal_requests_still_work_on_secure_target():
    assert s.Target(True).page("2")[0] == "In stock"
