from aisec_lab import load_lab_module

r = load_lab_module(__file__, "resolver")
INDEXES, LOCK = r.build_fixture()


def test_vulnerable_resolver_picks_attacker_version():
    res = r.resolve_highest_version("acme-billing-utils", INDEXES)
    assert (res.version, res.index) == ("99.0.0", "public")
    sink: list[str] = []
    r.install(res, INDEXES, sink)
    assert sink == [r.CANARY]


def test_normal_public_package_unaffected():
    res = r.resolve_highest_version("requests", INDEXES)
    assert res.index == "public" and res.version == "2.31.0"


def test_pinned_index_blocks():
    res = r.resolve_pinned_index("acme-billing-utils", INDEXES, {"acme-billing-utils": "private"})
    assert (res.version, res.index) == ("1.2.0", "private")
    sink: list[str] = []
    r.install(res, INDEXES, sink)
    assert sink == []


def test_pinned_index_misrouted_is_still_vulnerable():
    res = r.resolve_pinned_index("acme-billing-utils", INDEXES, {})  # forgot the routing rule
    assert res.index == "public"


def test_reserved_prefix_blocks_and_leaves_public_alone():
    a = r.resolve_reserved_prefix("acme-billing-utils", INDEXES, ("acme-",))
    b = r.resolve_reserved_prefix("requests", INDEXES, ("acme-",))
    assert a.index == "private" and b.index == "public"


def test_lock_with_hashes_blocks():
    res = r.resolve_with_lock("acme-billing-utils", INDEXES, LOCK)
    assert res.index == "private" and res.version == "1.2.0"


def test_lock_rejects_unlisted_and_mismatched():
    assert r.resolve_with_lock("evil-pkg", INDEXES, LOCK).version is None
    assert r.resolve_with_lock("requests", INDEXES, {"requests": "sha-other"}).version is None


def test_ide_quick_fix_suggests_public_name():
    hint = r.ide_quick_fix("acme-billing-utils", INDEXES)
    assert hint == "pip install acme-billing-utils==99.0.0"  # the pattern to distrust
    assert r.ide_quick_fix("no-such", INDEXES) is None


def test_not_found():
    assert r.resolve_highest_version("zzz", INDEXES).version is None
