from aisec_lab import load_lab_module

c = load_lab_module(__file__, "cache_lab")


def _pair(secure):
    o = c.Origin(secure)
    return o, c.Cache(o, secure)


def test_unkeyed_header_poisons_page_for_every_later_visitor():
    _, cache = _pair(False)
    cache.get("/", {"X-Forwarded-Host": "evil.example"})
    status, _, body, hit = cache.get("/")
    assert "https://evil.example/static/app.js" in body and hit == "HIT"


def test_secure_cache_and_origin_serve_clean_page_to_victim():
    _, cache = _pair(True)
    cache.get("/", {"X-Forwarded-Host": "evil.example"})
    assert "https://shop.lab.example/static/app.js" in cache.get("/")[2]


def test_cache_deception_leaks_victims_private_page_to_attacker():
    _, cache = _pair(False)
    cache.get("/account/nothing.css", {"Cookie": "FAKE-sess-victim"})
    status, _, body, hit = cache.get("/account/nothing.css")
    assert status == 200 and "FAKE-CARD-4111" in body and hit == "HIT"


def test_secure_setup_returns_404_and_never_caches_private_pages():
    _, cache = _pair(True)
    assert cache.get("/account/nothing.css", {"Cookie": "FAKE-sess-victim"})[0] == 404
    cache.get("/account", {"Cookie": "FAKE-sess-victim"})
    assert cache.get("/account")[0] == 302  # no cookie -> login, not victim's data


def test_vulnerable_cache_stores_private_no_store_page_because_path_looks_static():
    _, cache = _pair(False)
    cache.get("/account/x.css", {"Cookie": "FAKE-sess-victim"})
    status, headers, _ = cache.store[("/account/x.css",)]
    assert "no-store" in headers["Cache-Control"]  # the origin said no, the cache stored it anyway


def test_secure_cache_keys_on_forwarded_host_header():
    _, cache = _pair(True)
    cache.get("/", {"X-Forwarded-Host": "evil.example"})
    assert ("/", "evil.example") in cache.store and cache.get("/")[3] == "MISS"


def test_memcached_audit_flags_exposed_instance_and_passes_hardened_one():
    bad = c.audit_memcached({"listen": "0.0.0.0", "udp_port": 11211, "internet_facing": True})
    assert len(bad) == 5
    assert c.audit_memcached({"listen": "10.0.4.12", "udp_port": 0, "sasl": True, "tls": True}) == []
