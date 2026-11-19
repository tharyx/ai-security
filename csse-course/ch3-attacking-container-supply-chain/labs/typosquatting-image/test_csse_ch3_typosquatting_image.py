from pathlib import Path

import pytest
from aisec_lab import load_lab_module

ns = load_lab_module(__file__, "name_sim")
POLICY = ns.Policy.load(Path(__file__).parent / "fixtures/policy.json")
D = "@sha256:" + "f" * 64


def test_parse_docker_hub_shortcuts():
    r = ns.parse("nginx")
    assert (r.registry, r.namespace, r.name, r.tag) == ("docker.io", "library", "nginx", "latest")
    r = ns.parse("registry.corp.example:5000/team/api:1.2" + D)
    assert (r.registry, r.namespace, r.name, r.tag) == ("registry.corp.example:5000", "team", "api", "1.2") and r.digest


@pytest.mark.parametrize("bad", ["nqinx", "ngnix", "nginxx", "redis-official", "rn1cro", "ubunut"])
def test_look_alikes_are_flagged(bad):
    # rn1cro is not a popular lookalike: only the others must match
    flagged = bool(ns.check_name(bad, list(POLICY.popular)))
    assert flagged == (bad != "rn1cro")


def test_exact_official_name_is_not_flagged():
    assert ns.check_name("nginx", list(POLICY.popular)) == []
    assert ns.check_name("library/nginx:1.27", list(POLICY.popular)) == []


def test_same_name_in_user_namespace_is_flagged():
    got = ns.check_name("nginx/nginx", list(POLICY.popular))
    assert got and "namespace" in got[0].reason


def test_homoglyph_rn_for_m():
    assert ns.check_name("postgres", ["library/postgres"]) == []
    assert ns.check_name("alpine", ["library/alpine"]) == []
    assert ns.check_name("rnodes", ["library/modes"])  # rn -> m


def test_unrelated_name_is_clean():
    assert ns.check_name("registry.corp.example/team/billing", list(POLICY.popular)) == []


def test_policy_flags_registry_and_digest():
    p = ns.evaluate("evil.example/library/nginx", POLICY)
    assert any("allowlist" in x for x in p) and any("digest" in x for x in p)


def test_clean_reference_passes_policy():
    assert ns.evaluate("registry.corp.example/team/api" + D, POLICY) == []


def test_levenshtein_basics():
    assert ns.levenshtein("nginx", "nqinx") == 1 and ns.levenshtein("abc", "abc") == 0
    assert ns.is_transposition("ngnix", "nginx") and not ns.is_transposition("nginx", "nginx")
