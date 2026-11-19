from pathlib import Path

from aisec_lab import load_lab_module

b = load_lab_module(__file__, "bddlite")
steps = load_lab_module(__file__, "steps")
sim = load_lab_module(__file__, "app_sim")
FEAT = Path(__file__).resolve().parent / "features"


def run(vulnerable: bool):
    b.STEPS.clear()
    steps.register(b.step)
    return b.run_dir(FEAT, lambda: {"app": sim.App(vulnerable=vulnerable)})


def by_status(outs):
    d = {}
    for o in outs:
        d.setdefault(o.status, []).append(o.scenario)
    return d


def test_parser_reads_background_tags_and_outline_rows():
    f = b.parse((FEAT / "injection_and_headers.feature").read_text())
    assert f.background == ["a fresh application"]
    names = [s.name for s in f.scenarios]
    assert sum(n.startswith("Injection payloads") for n in names) == 3   # 3 example rows
    inj = next(s for s in f.scenarios if "<script>" in s.name)
    assert 'I search for "<script>x</script>"' in inj.steps and "@injection" in inj.tags
    assert "@security" in inj.tags      # feature tags are inherited


def test_secure_app_passes_everything_except_wip_skipped():
    outs = run(False)
    st = by_status(outs)
    assert "failed" not in st and "undefined" not in st
    assert len(st["skipped"]) == 1 and len(st["passed"]) == 8
    assert b.exit_code(outs) == 0


def test_vulnerable_app_fails_the_threat_scenarios():
    outs = run(True)
    failed = " | ".join(by_status(outs)["failed"])
    for threat in ("T-01", "T-09", "T-02", "T-10", "T-04", "T-06"):
        assert threat in failed
    assert b.exit_code(outs) == 1


def test_failure_message_explains_what_was_wrong():
    outs = run(True)
    msg = next(o.message for o in outs if "T-09" in o.scenario)
    assert "no such user" in msg


def test_undefined_step_is_reported_not_silently_passed():
    b.STEPS.clear()
    feat = b.parse("Feature: x\n  Scenario: s\n    Given something nobody implemented\n")
    outs = b.run_feature(feat, dict)
    assert outs[0].status == "undefined" and b.exit_code(outs) == 1


def test_skip_tags_can_be_changed():
    b.STEPS.clear()
    steps.register(b.step)
    f = b.parse((FEAT / "injection_and_headers.feature").read_text())
    outs = b.run_feature(f, lambda: {"app": sim.App()}, skip_tags=())
    assert any(o.status == "failed" and "429" in o.message for o in outs)   # the @wip scenario really fails


def test_lockout_resets_after_successful_login_in_simulator():
    app = sim.App()
    for _ in range(3):
        app.handle("POST", "/login", form={"user": "alice", "password": "bad"})
    ok = app.handle("POST", "/login", form={"user": "alice", "password": "correct-horse-battery"})
    assert ok.status == 200 and app.failures["alice"] == 0


def test_cookie_step_checks_each_flag():
    app = sim.App(vulnerable=True)
    resp = app.handle("POST", "/login", form={"user": "bob", "password": "tr0ub4dor-and-3"})
    b.STEPS.clear()
    steps.register(b.step)
    ctx = {"app": app, "resp": resp}
    try:
        b._run_step('the cookie "sid" has the flags "HttpOnly"', ctx)
    except AssertionError as e:
        assert "HttpOnly" in str(e)
    else:
        raise AssertionError("expected a failed assertion")
