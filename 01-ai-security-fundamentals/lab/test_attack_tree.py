"""Tests for the attack-tree lab (lesson 03).

Run from the repository root:
    python -m pytest 01-ai-security-fundamentals -v
"""

import math

import pytest

from aisec_lab import load_lab_module

at = load_lab_module(__file__, "attack_tree")


def tree():
    return at.helpdesk_tree()


def test_and_or_maths_on_a_two_leaf_tree():
    a, b = at.Node("a", "a", p=0.5, cost=2), at.Node("b", "b", p=0.4, cost=3)
    assert at.probability(at.Node("x", "x", "AND", children=[a, b])) == pytest.approx(0.2)
    assert at.probability(at.Node("y", "y", "OR", children=[a, b])) == pytest.approx(0.7)
    assert at.cheapest_cost(at.Node("x", "x", "AND", children=[a, b])) == 5
    assert at.cheapest_cost(at.Node("y", "y", "OR", children=[a, b])) == 2


def test_cheapest_attack_is_the_cross_tenant_retrieval():
    assert at.cheapest_path(tree()) == ["rag_no_acl"]


def test_best_single_control_is_the_retrieval_acl_filter():
    best_leaf, _, p_after = at.rank_controls(tree())[0]
    assert best_leaf == "rag_no_acl"
    assert p_after < at.probability(tree())


def test_blocking_one_exfiltration_channel_barely_helps():
    before = at.probability(tree())
    after = at.probability(tree(), frozenset({"send_tool"}))
    assert before - after < 0.01  # the other channels are still open (OR node)


def test_cutting_one_leg_of_an_and_branch_kills_that_whole_branch():
    injection = tree().children[0]
    assert at.probability(injection, frozenset({"send_mail"})) == 0.0


def test_soft_control_on_model_behaviour_lowers_but_does_not_remove_risk():
    soft = at.probability(tree(), overrides={"model_follows": 0.1})
    assert 0 < soft < at.probability(tree())


def test_steps_with_no_hard_control_cannot_be_mitigated_in_the_ranking():
    ranked_leaves = {leaf for leaf, _, _ in at.rank_controls(tree())}
    assert "model_follows" not in ranked_leaves


def test_hard_controls_on_every_branch_make_the_goal_impossible():
    m = frozenset({"rag_no_acl", "send_mail", "data_in_logs"})
    assert at.probability(tree(), m) == 0.0
    assert at.cheapest_cost(tree(), m) == math.inf
    assert at.cheapest_path(tree(), m) == []
