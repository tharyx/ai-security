"""Tests for vetting.py and depconfusion.py (run offline)."""

from __future__ import annotations

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "vetting")
dc = load_lab_module(__file__, "depconfusion")
FX = v.load_fixture()


def verdicts():
    return {x.name: x for x in v.vet_requested([p["name"] for p in FX["registry"]], FX)}


# ----------------------------------------------------------------- vetting


def test_levenshtein_and_transposition():
    assert v.levenshtein("kitten", "sitting") == 3
    assert v.levenshtein("abc", "abc") == 0
    assert v.transposed("reqeusts", "requests")
    assert not v.transposed("requests", "requests")


def test_normalize_follows_pep503_style():
    assert v.normalize("Scikit_Learn") == "scikit-learn"
    assert v.normalize("a..b__c") == "a-b-c"


def test_typosquat_detection():
    pops = FX["popular_names"]
    assert v.typosquat_target("reqeusts", pops) == ("requests", "typosquat_1")
    assert v.typosquat_target("langchian", pops)[0] == "langchain"
    assert v.typosquat_target("scikit_learn", pops) is None            # same normalized name
    assert v.typosquat_target("scikitlearn", pops) == ("scikit-learn", "separator_trick")
    assert v.typosquat_target("requests-official", pops) == ("requests", "combosquat")
    assert v.typosquat_target("python-flask", pops) == ("flask", "combosquat")
    assert v.typosquat_target("totally-different", pops) is None


def test_popular_packages_are_allowed():
    r = verdicts()
    assert r["requests"].decision == "allow" and r["numpy"].decision == "allow"


def test_typosquats_with_install_script_are_blocked():
    r = verdicts()
    assert r["reqeusts"].decision == "block"
    assert any("imitates 'requests'" in x for x in r["reqeusts"].reasons)
    assert any("runs code at install time" in x for x in r["reqeusts"].reasons)
    assert r["langchian"].decision == "block"


def test_slopsquatting_name_is_flagged_even_without_other_signals():
    r = verdicts()["fastjson-llm-utils"]
    assert any("LLMs invent" in x for x in r.reasons)
    assert r.decision in ("review", "block")
    assert r.score >= 60  # new + hallucinated + single maintainer + no repo + few downloads


def test_borderline_packages_go_to_review_not_block():
    r = verdicts()
    assert r["brand-new-helper"].decision in ("allow", "review")
    assert r["small-but-honest-lib"].decision == "allow"


def test_name_not_in_registry_is_blocked_as_invented():
    out = v.vet_requested(["totally-made-up-ai-pkg"], FX)[0]
    assert out.decision == "block" and "invented" in out.reasons[0]


def test_score_is_capped_and_reasons_explain_it():
    r = verdicts()["acme-ml-utils"]
    assert 0 <= r.score <= 100 and r.reasons


def test_internal_name_on_public_index_is_reported():
    assert v.internal_names_on_public(["acme-ml-utils", "acme-private-thing"], FX) == ["acme-ml-utils"]


# ----------------------------------------------------------------- dependency confusion

REQS = "acme-ml-utils\nnumpy\n"


def test_naive_resolver_picks_the_attackers_public_package():
    private, public = dc.sample_indexes()
    res = {r.name: r for r in dc.install(REQS, [private, public], "naive")}
    assert res["acme-ml-utils"].index == "public"
    assert res["acme-ml-utils"].version == "99.0.0"
    assert b"HARMLESS-INSTALL-HOOK-MARKER" in public.artifact("acme-ml-utils", "99.0.0")


def test_naive_resolver_is_fine_when_the_name_is_not_attacked():
    private, public = dc.sample_indexes()
    res = {r.name: r for r in dc.install(REQS, [private, public], "naive")}
    assert res["numpy"].version == "2.1.0"


def test_scoped_resolver_keeps_internal_names_on_the_private_index():
    private, public = dc.sample_indexes()
    res = {r.name: r for r in dc.install(REQS, [private, public], "scoped",
                                         internal_scopes={"acme-*": "private"})}
    assert res["acme-ml-utils"].index == "private" and res["acme-ml-utils"].version == "1.2.0"
    assert res["numpy"].index == "public"


def test_scoped_resolver_never_falls_back_to_public_for_internal_names():
    private, public = dc.sample_indexes()
    del private.packages["acme-ml-utils"]  # private index is down / package removed
    res = dc.install("acme-ml-utils\n", [private, public], "scoped", internal_scopes={"acme-*": "private"})[0]
    assert not res.ok and res.version is None


def test_locked_resolver_rejects_requirements_without_hashes():
    private, public = dc.sample_indexes()
    res = dc.install("acme-ml-utils==1.2.0\n", [private, public], "locked")[0]
    assert not res.ok and "no hash" in res.note


def test_locked_resolver_installs_only_the_pinned_artifact():
    private, public = dc.sample_indexes()
    line = dc.lock_line("acme-ml-utils", "1.2.0", private.artifact("acme-ml-utils", "1.2.0"))
    res = dc.install(line + "\n", [private, public], "locked")[0]
    assert res.ok and res.index == "private"


def test_hash_mismatch_is_detected_when_artifact_is_swapped():
    private, public = dc.sample_indexes()
    line = dc.lock_line("acme-ml-utils", "1.2.0", private.artifact("acme-ml-utils", "1.2.0"))
    private.packages["acme-ml-utils"]["1.2.0"] = b"tampered bytes"   # registry compromise
    res = dc.install(line + "\n", [private, public], "locked")[0]
    assert not res.ok and "HASH MISMATCH" in res.note


def test_attackers_version_cannot_satisfy_a_pin_even_with_a_valid_looking_hash():
    private, public = dc.sample_indexes()
    evil = public.artifact("acme-ml-utils", "99.0.0")
    line = dc.lock_line("acme-ml-utils", "1.2.0", private.artifact("acme-ml-utils", "1.2.0"))
    res = dc.install(line + "\n", [public], "locked")[0]   # only the public index is visible
    assert not res.ok and dc.sha256(evil) not in line


def test_parse_requirements_handles_continuations_and_comments():
    text = "numpy==2.1.0 \\\n    --hash=sha256:aa --hash=sha256:bb  # comment\n\nflask\n"
    reqs = dc.parse_requirements(text)
    assert reqs[0].name == "numpy" and reqs[0].pin == "2.1.0" and reqs[0].hashes == ["aa", "bb"]
    assert reqs[1].name == "flask" and reqs[1].pin is None
