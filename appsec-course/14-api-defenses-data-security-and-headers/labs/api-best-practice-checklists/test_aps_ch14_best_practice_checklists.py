from pathlib import Path

from aisec_lab import load_lab_module

bp = load_lab_module(__file__, "bp_checklists")
FX = Path(__file__).resolve().parent / "fixtures"


def ids(style, variant):
    return {f.rule for f in bp.check(style, bp.load(FX / f"{style}_{variant}.json"))}


def test_weak_graphql_exposes_introspection_and_missing_limits():
    got = ids("graphql", "weak")
    assert {"GQL-01", "GQL-03", "GQL-05", "GQL-07"} <= got


def test_hardened_configs_pass_every_rule():
    for style in ("graphql", "soap", "rest"):
        assert ids(style, "hardened") == set(), style


def test_weak_soap_allows_xxe_and_signature_wrapping():
    got = ids("soap", "weak")
    assert {"SOAP-01", "SOAP-02", "SOAP-07", "SOAP-06"} <= got


def test_weak_rest_has_unauthenticated_admin_route_and_bola():
    findings = bp.check("rest", bp.load(FX / "rest_weak.json"))
    msgs = " ".join(f.message for f in findings)
    assert "/v2/admin/export" in msgs and "/v2/orders/{id}" in msgs
    assert "v1" in msgs  # zombie API version still live


def test_gate_fails_weak_and_passes_hardened():
    for style in ("graphql", "soap", "rest"):
        assert bp.gate(bp.check(style, bp.load(FX / f"{style}_weak.json"))) == 1
        assert bp.gate(bp.check(style, bp.load(FX / f"{style}_hardened.json"))) == 0


def test_depth_limit_blocks_deep_query_only_when_configured():
    deep = "query { a { b { c { d { e { f { g { h { i } } } } } } } } }"
    assert bp.graphql_query_depth(deep) == 8
    assert bp.enforce_graphql_limits(deep, bp.load(FX / "graphql_weak.json"))[0] is True
    assert bp.enforce_graphql_limits(deep, bp.load(FX / "graphql_hardened.json"))[0] is False


def test_alias_brute_force_is_rejected_by_alias_limit():
    brute = "mutation { " + " ".join(f'a{i}: login(pin: "{i}") {{ ok }}' for i in range(30)) + " }"
    assert bp.count_aliases(brute) == 30
    ok, msg = bp.enforce_graphql_limits(brute, bp.load(FX / "graphql_hardened.json"))
    assert not ok and "aliases" in msg


def test_arguments_and_strings_are_not_counted_as_aliases():
    q = 'query { user(id: "a: b") { name } }'
    assert bp.count_aliases(q) == 0
