"""Tests for the TruffleHog-style scanner (offline verification)."""

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "truffle_lite")


def run(**kw):
    return t.scan_history(t.HISTORY, t.FakeProvider(live={t.LIVE_KEY}), **kw)


def test_secret_removed_in_later_commit_is_still_found_in_history():
    f = run()
    assert any(x.commit == "b2" and x.file == "app.py" for x in f)


def test_latest_checkout_scan_misses_the_removed_key():
    cur = t.current_tree_secrets(t.HISTORY)
    # app.py was rewritten, so only old.env (revoked key) and notify.py remain visible
    assert ("aws", "app.py") not in cur and ("aws", "old.env") in cur


def test_verification_statuses():
    st = {(x.commit, x.file): x.status for x in run()}
    assert st[("b2", "app.py")] == "verified"
    assert st[("b2", "old.env")] == "unverified"
    assert st[("d4", "notify.py")] == "unknown"


def test_only_verified_filter():
    f = run(only_verified=True)
    assert len(f) == 1 and f[0].commit == "b2"


def test_triage_buckets():
    b = t.triage(run())
    assert len(b["rotate-now"]) == 1 and len(b["review"]) == 1 and len(b["likely-dead"]) == 1


def test_previews_do_not_contain_full_secret():
    assert all(t.LIVE_KEY not in x.secret_preview for x in run())


def test_provider_is_called_per_finding_without_network():
    p = t.FakeProvider(live=set())
    t.scan_history(t.HISTORY, p)
    assert p.calls == 3


def test_no_live_keys_means_nothing_to_rotate_now():
    f = t.scan_history(t.HISTORY, t.FakeProvider(live=set()))
    assert t.triage(f)["rotate-now"] == []
