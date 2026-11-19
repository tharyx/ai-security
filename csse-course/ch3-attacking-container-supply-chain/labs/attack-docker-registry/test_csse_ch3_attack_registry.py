from aisec_lab import load_lab_module

rg = load_lab_module(__file__, "registry")
atk = load_lab_module(__file__, "attacker")
TOKENS = {"ci": ["repository:shop/*:pull,push,delete"], "reader": ["repository:shop/*:pull"], "admin": ["registry:catalog:*", "repository:shop/*:pull"]}
H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731


def seed(reg):
    reg.put_image("shop/api", "1.0", rg.sample_manifest("1.0", secret_env="DB_PASSWORD=FAKE"))
    reg.put_image("shop/web", "2.3", rg.sample_manifest("2.3"))
    return reg


def hardened():
    return seed(rg.Registry(auth=True, require_tls=True, immutable_tags=True, tokens=TOKENS))


def test_open_registry_lists_everything_and_leaks_secret():
    info = atk.enumerate_registry(seed(rg.Registry()))
    assert info["repos"] == {"shop/api": ["1.0"], "shop/web": ["2.3"]}
    assert info["secrets"] == [("shop/api:1.0", "DB_PASSWORD")]


def test_open_registry_accepts_tag_overwrite():
    reg = seed(rg.Registry())
    old = reg.tags["shop/api"]["1.0"]
    assert atk.poison_tag(reg, "shop/api", "1.0").status == 201
    assert reg.tags["shop/api"]["1.0"] != old


def test_open_registry_allows_delete_by_anyone():
    reg = seed(rg.Registry())
    digest = reg.tags["shop/web"]["2.3"]
    assert reg.handle("DELETE", f"/v2/shop/web/manifests/{digest}").status == 202
    assert "shop/web" not in reg.handle("GET", "/v2/_catalog").body["repositories"] or reg.tags["shop/web"] == {}


def test_hardened_blocks_anonymous_and_returns_challenge():
    r = hardened().handle("GET", "/v2/_catalog", scheme="https")
    assert r.status == 401 and "WWW-Authenticate" in r.headers


def test_hardened_requires_tls():
    r = hardened().handle("GET", "/v2/shop/api/tags/list", headers=H("reader"), scheme="http")
    assert r.status == 403 and "TLS" in r.body["errors"][0]["message"]


def test_reader_can_pull_but_not_push():
    reg = hardened()
    assert reg.handle("GET", "/v2/shop/api/tags/list", headers=H("reader"), scheme="https").status == 200
    assert reg.handle("PUT", "/v2/shop/api/manifests/9", headers=H("reader"), body=rg.sample_manifest("9"), scheme="https").status == 401


def test_catalog_needs_its_own_scope():
    reg = hardened()
    assert reg.handle("GET", "/v2/_catalog", headers=H("reader"), scheme="https").status == 401
    assert reg.handle("GET", "/v2/_catalog", headers=H("admin"), scheme="https").status == 200


def test_immutable_tags_stop_overwrite_even_for_ci():
    reg = hardened()
    assert atk.poison_tag(reg, "shop/api", "1.0", headers=H("ci"), scheme="https").status == 409
    assert reg.handle("PUT", "/v2/shop/api/manifests/1.1", headers=H("ci"), body=rg.sample_manifest("1.1"), scheme="https").status == 201


def test_pushing_the_same_content_to_an_immutable_tag_is_idempotent():
    reg = hardened()
    same = reg.manifests["shop/api"][reg.tags["shop/api"]["1.0"]]
    assert reg.handle("PUT", "/v2/shop/api/manifests/1.0", headers=H("ci"), body=same, scheme="https").status == 201


def test_scope_does_not_leak_to_other_repo_namespace():
    reg = hardened()
    reg.put_image("other/db", "1", rg.sample_manifest("x"))
    assert reg.handle("GET", "/v2/other/db/tags/list", headers=H("reader"), scheme="https").status == 401


def test_get_by_digest_matches_tag():
    reg = seed(rg.Registry())
    d = reg.tags["shop/api"]["1.0"]
    assert reg.handle("GET", f"/v2/shop/api/manifests/{d}").body == reg.handle("GET", "/v2/shop/api/manifests/1.0").body
