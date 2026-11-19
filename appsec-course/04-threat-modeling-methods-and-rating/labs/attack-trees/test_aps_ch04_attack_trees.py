import math
from pathlib import Path

from aisec_lab import load_lab_module

at = load_lab_module(__file__, "attack_tree")
TREE = at.load(Path(__file__).resolve().parent / "fixtures" / "account_takeover.json")


def test_fixture_tree_is_valid_and_bad_trees_are_rejected():
    assert at.validate(TREE) == []
    bad = at.from_dict({"id": "r", "label": "r", "kind": "AND", "children": [
        {"id": "a", "label": "a", "prob": 1.5, "children": [{"id": "b", "label": "b"}]}]})
    errs = " ".join(at.validate(bad))
    assert "GATE_NEEDS_TWO_CHILDREN" in errs and "LEAF_WITH_CHILDREN" in errs and "PROB_OUT_OF_RANGE" in errs


def test_and_node_needs_all_steps_or_node_needs_any():
    stuff = TREE.children[1]
    cost, prob = at.evaluate(stuff)
    assert cost == 50 and math.isclose(prob, 0.9 * 0.6 * 0.7)
    reset = TREE.children[2]
    cost, prob = at.evaluate(reset)
    assert cost == 200 and math.isclose(prob, 1 - 0.8 * 0.85)


def test_cheapest_attack_without_controls_is_credential_stuffing():
    assert at.evaluate(TREE)[0] == 50
    assert at.cheapest_path(TREE) == ["Buy a leaked credential list", "Login has no rate limit", "Account has no MFA"]


def test_rate_limit_moves_attacker_to_next_cheapest_branch():
    assert at.evaluate(TREE, {"rate_limit"})[0] == 200
    assert at.cheapest_path(TREE, {"rate_limit"}) == ["Poison reset link via Host header"]


def test_passkeys_is_the_best_single_control_here():
    name, new_cost = at.best_single_control(TREE, ["rate_limit", "passkeys", "csp", "httponly"])
    assert name == "passkeys" and new_cost == 200


def test_blocking_every_route_makes_goal_unreachable():
    all_controls = {"passkeys", "rate_limit", "csprng_tokens", "fixed_base_url", "csp"}
    assert at.evaluate(TREE, all_controls) == (math.inf, 0.0)
    assert at.cheapest_path(TREE, all_controls) == []


def test_scenarios_are_minimal_cut_sets_and_budget_filter():
    sc = at.scenarios(TREE)
    assert len(sc) == 5 and frozenset({"leak", "nolimit", "nomfa"}) in sc
    cheap = at.within_budget(TREE, 250)
    assert [c for c, _ in cheap] == [50, 200]


def test_render_marks_blocked_branches():
    text = at.render(TREE, {"passkeys"})
    assert "[OR] Take over a customer account" in text and "blocked" in text
