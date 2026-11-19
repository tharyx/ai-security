from aisec_lab import load_lab_module

fb = load_lab_module(__file__, "fakebrowser")
B = fb.FakeBrowser()


def run(build, payloads=None):
    app = fb.CommentBoard(build)
    for p in payloads or fb.attacker_payloads():
        app.post(p)
    page, headers = app.render()
    return B.load(page, headers)


def test_stored_xss_steals_cookie_without_csp():
    res = run("vulnerable")
    assert fb.stolen(res)
    assert len([e for e in res.executed if "steal" in e or "evil" in e]) == 4


def test_nonce_csp_blocks_every_injected_script_even_with_the_escaping_bug():
    res = run("csp_only")
    assert not fb.stolen(res)
    assert f"inline:{fb.APP_SCRIPT}" in res.executed and "external:/static/app.js" in res.executed
    assert len(res.blocked) == 4


def test_unsafe_inline_csp_does_not_stop_xss():
    assert fb.stolen(run("unsafe_inline"))


def test_report_only_reports_but_does_not_block():
    res = run("report_only")
    assert fb.stolen(res) and len(res.reports) >= 4


def test_escaping_plus_csp_leaves_nothing_to_block():
    res = run("fixed")
    assert not fb.stolen(res) and res.blocked == []


def test_nonce_changes_every_response():
    app = fb.CommentBoard("fixed")
    assert app.render()[1]["Content-Security-Policy"] != app.render()[1]["Content-Security-Policy"]


def test_static_nonce_lets_attacker_reuse_it():
    res = run("static_nonce", ['<script nonce="static123">steal(document.cookie)</script>'])
    assert fb.stolen(res)


def test_hash_source_allows_only_the_exact_script():
    csp = {"Content-Security-Policy": f"script-src {fb.sha256_source('ok()')}"}
    res = B.load("<script>ok()</script><script>ok() </script>", csp)
    assert res.executed == ["inline:ok()"] and len(res.blocked) == 1


def test_host_allowlist_without_strict_dynamic_allows_listed_cdn():
    csp = {"Content-Security-Policy": "script-src 'self' https://cdn.example"}
    res = B.load('<script src="https://cdn.example/lib.js"></script><script src="https://evil.attacker.test/x.js"></script>', csp)
    assert res.executed == ["external:https://cdn.example/lib.js"]
