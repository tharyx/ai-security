import copy
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

pm = load_lab_module(__file__, "pci_mapper")
FIX = Path(__file__).parent / "fixtures"
TASKS = pm.load_tasks(FIX / "pci_hardening_playbook.yml")
MAPPING = pm.load_mapping(FIX / "pci_mapping.yml")


def rows(report):
    return {r["req"]: r for r in report["rows"]}


def test_mapping_is_valid():
    assert pm.validate_mapping(MAPPING) == []


def test_direct_coverage_for_core_requirements():
    r = rows(pm.coverage(TASKS, MAPPING))
    for req in ("2.2.2", "2.2.4", "2.2.6", "2.2.7", "8.3.6", "10.2.1", "10.6.1"):
        assert r[req]["status"] == "covered", req


def test_supporting_only_is_partial():
    r = rows(pm.coverage(TASKS, MAPPING))
    assert r["6.3.3"]["status"] == "partial"


def test_gaps_are_reported_not_hidden():
    r = rows(pm.coverage(TASKS, MAPPING))
    for req in ("5.2.1", "11.5.2", "7.2.1", "2.2.1"):
        assert r[req]["status"] == "gap"


def test_unmapped_tasks_are_listed():
    assert "Install a text editor for the admins" in pm.coverage(TASKS, MAPPING)["unmapped_tasks"]


def test_removing_a_task_drops_coverage():
    fewer = [t for t in TASKS if "time_sync" not in t["tags"]]
    assert rows(pm.coverage(fewer, MAPPING))["10.6.1"]["status"] == "gap"


def test_unknown_requirement_id_rejected():
    bad = copy.deepcopy(MAPPING)
    bad["mappings"]["time_sync"].append({"req": "99.9.9", "strength": "direct"})
    with pytest.raises(ValueError):
        pm.coverage(TASKS, bad)


def test_report_carries_the_disclaimer_and_version():
    text = pm.render_text(pm.coverage(TASKS, MAPPING))
    assert "not a compliance statement" in text and "v4.0.1" in text


def test_percentage_matches_counts():
    rep = pm.coverage(TASKS, MAPPING)
    assert rep["covered_pct"] == round(100 * rep["counts"]["covered"] / len(rep["rows"]), 1)
