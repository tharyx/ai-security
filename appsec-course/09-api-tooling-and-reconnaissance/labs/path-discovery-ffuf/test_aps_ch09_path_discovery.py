from aisec_lab import load_lab_module

f = load_lab_module(__file__, "ffuflite")

KNOWN = {
    "/api/v1/login": (200, "login form"),
    "/api/v1/products": (200, "product list"),
    "/api/v1/admin": (401, "unauthorized"),
    "/api/v1/debug": (200, "DEBUG MODE ON — leaks config"),
}


def test_fuzz_finds_existing_paths_and_hides_404s():
    handle = f.make_router(KNOWN)
    hits = f.fuzz("/api/v1/FUZZ", f.DEFAULT_WORDLIST, handle)
    found = {h.word for h in hits}
    assert "login" in found and "products" in found and "debug" in found
    # admin returns 401 (not 404), so discovery still sees it exists
    assert "admin" in found
    # a word with no route is filtered out
    assert "backup" not in found


def test_requires_fuzz_token():
    handle = f.make_router(KNOWN)
    try:
        f.fuzz("/api/v1/login", ["x"], handle)
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_match_codes_keeps_only_those_statuses():
    handle = f.make_router(KNOWN)
    hits = f.fuzz("/api/v1/FUZZ", f.DEFAULT_WORDLIST, handle, match_codes={200})
    assert all(h.status == 200 for h in hits)
    assert "admin" not in {h.word for h in hits}  # admin is 401


def test_hidden_unknown_mode_makes_protected_paths_indistinguishable():
    # The defensive extreme: protected endpoints return 404 like unknown ones.
    handle = f.make_router(KNOWN, hide_unknown=True)
    hits = f.fuzz("/api/v1/FUZZ", f.DEFAULT_WORDLIST, handle)
    found = {h.word for h in hits}
    assert "admin" not in found  # now hidden
    assert "login" in found      # public ones still visible


def test_debug_endpoint_length_differs_signalling_a_leak():
    handle = f.make_router(KNOWN)
    hits = {h.word: h for h in f.fuzz("/api/v1/FUZZ", f.DEFAULT_WORDLIST, handle)}
    assert hits["debug"].length > hits["login"].length


def test_filter_codes_drops_specified_status():
    handle = f.make_router(KNOWN)
    hits = f.fuzz("/api/v1/FUZZ", f.DEFAULT_WORDLIST, handle, filter_codes={401, 404})
    assert "admin" not in {h.word for h in hits}
