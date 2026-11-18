"""The control matrix is data that people and tools depend on, so it gets tests too.

Run from the repository root:
    python -m pytest 09-enterprise-architecture -v
"""

import csv
import io

import pytest
from pydantic import ValidationError

from aisec_lab import load_lab_module

reviewer = load_lab_module(__file__, "reviewer")
MATRIX = reviewer.load_matrix()
IDS = [c.id for c in MATRIX]


def test_matrix_is_not_trivial():
    assert len(MATRIX) >= 15
    assert {c.family for c in MATRIX} >= {"identity", "network", "data", "guardrails",
                                          "tools-agents", "logging", "operations"}


def test_control_ids_are_unique():
    assert len(IDS) == len(set(IDS))


@pytest.mark.parametrize("control", MATRIX, ids=IDS)
def test_every_control_maps_to_all_three_clouds(control):
    assert set(control.clouds) == set(reviewer.CLOUDS), "exactly aws, azure and gcp"
    for cloud in reviewer.CLOUDS:
        mapping = control.clouds[cloud]
        assert mapping.services.strip(), f"{control.id} has no {cloud} services"
        assert mapping.evidence.strip(), f"{control.id} has no {cloud} evidence"


@pytest.mark.parametrize("control", MATRIX, ids=IDS)
def test_every_control_has_an_automated_check(control):
    assert control.check in reviewer.CHECKS, f"{control.id}: no reviewer check named {control.check}"


def test_every_check_is_used_by_exactly_one_control():
    used = [c.check for c in MATRIX]
    assert sorted(used) == sorted(reviewer.CHECKS), "orphan check or duplicate mapping"


@pytest.mark.parametrize("control", MATRIX, ids=IDS)
def test_every_control_states_an_outcome_and_an_owner(control):
    assert len(control.outcome.split()) >= 8
    assert control.responsibility in {"customer", "shared", "provider"}


def test_matrix_rejects_unknown_fields():
    bad = {"controls": [{"id": "X-1", "family": "x", "title": "t", "severity": "high",
                         "responsibility": "customer", "check": "key_rotation",
                         "outcome": "o", "clouds": {}, "sevrity": "low"}]}
    with pytest.raises(ValidationError):  # "sevrity" is a typo
        reviewer.parse_matrix(bad)


def test_csv_export_round_trips_every_control():
    rows = list(csv.DictReader(io.StringIO(reviewer.export_csv(MATRIX))))
    assert [r["id"] for r in rows] == IDS
    for row, ctrl in zip(rows, MATRIX):
        for cloud in reviewer.CLOUDS:
            assert row[cloud] == ctrl.clouds[cloud].services
