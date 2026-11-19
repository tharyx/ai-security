import math
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "diagrams")
TREE = (Path(__file__).resolve().parent / "fixtures" / "steal_customer_data.tree").read_text(encoding="utf-8")


def tree():
    return d.parse_tree(TREE)


def test_sequence_diagram_is_valid_plantuml():
    seq = d.sequence_diagram("t", [("actor", "User"), ("participant", "Web App")],
                             [("User", "Web App", "login"), ("Web App", "User", "return ok")])
    assert d.lint_plantuml(seq) == []
    assert "Web_App --> User: return ok" in seq


def test_class_diagram_contains_members_and_relations():
    uml = d.class_diagram({"Order": ["- owner_id: int", "+ total()"], "Customer": ["- id: int"]},
                          [("Order", "-->", "Customer")])
    assert "class Order {" in uml and "  - owner_id: int" in uml and "Order --> Customer" in uml


def test_misuse_case_diagram_links_threat_to_use_case():
    uc = d.misuse_case_diagram(["Customer"], ["Attacker"], ["View orders"],
                               [("Read other orders", "View orders")], [("Attacker", "Read other orders")])
    assert "Read_other_orders ..> View_orders : <<threatens>>" in uc
    assert d.lint_plantuml(uc) == []


def test_linter_catches_undeclared_participant_and_missing_end():
    problems = d.lint_plantuml("@startuml\nactor A\nA -> B: hi\n")
    assert "undeclared participant: B" in problems and "last line must be @enduml" in problems


def test_cheapest_attack_is_bola_on_the_unmitigated_tree():
    cost, path = d.cheapest(tree())
    assert (cost, path) == (10, ["L3"])


def test_each_control_pushes_the_attacker_to_a_costlier_path():
    t = tree()
    costs = []
    for controls in [set(), {"L3"}, {"L3", "L2"}, {"L3", "L2", "L5"}]:
        d.mitigate(t, controls)
        costs.append(d.cheapest(t)[0])
    assert costs == [10, 50, 300, 2000]


def test_blocking_one_child_of_an_and_gate_blocks_that_branch():
    t = d.mitigate(tree(), {"L2", "L3", "L5", "L6"})
    assert d.cheapest(t) == (math.inf, []) and d.probability(t) == 0.0


def test_probability_or_and_math():
    t = d.parse_tree("OR: goal\n  LEAF: a [id=A, p=0.5]\n  AND: both\n    LEAF: b [id=B, p=0.5]\n"
                     "    LEAF: c [id=C, p=0.5]\n")
    assert d.probability(t) == pytest.approx(1 - 0.5 * 0.75)


def test_dsl_errors_are_reported_not_ignored():
    with pytest.raises(ValueError):
        d.parse_tree("OR: goal\n  LEAF: no id here\n")
    with pytest.raises(ValueError):
        d.parse_tree("LEAF: a [id=A]\n  LEAF: child of a leaf [id=B]\n")
    with pytest.raises(KeyError):
        d.mitigate(tree(), {"L99"})


def test_renderers_mark_blocked_leaves():
    t = d.mitigate(tree(), {"L3"})
    mm = d.to_mermaid(t)
    assert mm.startswith("graph TD") and "class L3 blocked" in mm
    assert "L3 [" in d.to_dot(t) and "style=dashed" in d.to_dot(t)
