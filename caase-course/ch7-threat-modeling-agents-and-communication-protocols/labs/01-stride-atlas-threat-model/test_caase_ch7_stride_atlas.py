"""Run: python -m pytest caase-course/ch7-threat-modeling-agents-and-communication-protocols"""
from __future__ import annotations

import copy

from aisec_lab import load_lab_module

tm = load_lab_module(__file__, "threat_model")


def test_deployment_is_valid():
    arch, _ = tm.load()
    assert tm.validate(arch) == []


def test_validation_catches_errors():
    arch, _ = tm.load()
    bad = copy.deepcopy(arch)
    bad["flows"].append({"id": "F99", "source": "user", "target": "ghost"})
    bad["flows"].append({"id": "F98", "source": "ctx", "target": "payments"})
    bad["elements"][0]["zone"] = "mars"
    p = tm.validate(bad)
    assert any("ghost" in x for x in p) and any("mars" in x for x in p)
    assert any("one end" in x for x in p)


def test_crossings_show_untrusted_data_moving_up():
    arch, _ = tm.load()
    c = tm.crossings(arch)
    assert c["F5"] > 0          # partner (0) -> orchestrator (3)
    assert "F2" not in c        # same zone
    assert c["F4"] < 0          # platform (3) -> tools (2)


def test_every_stride_letter_is_found_and_each_has_atlas_and_asi():
    arch, lib = tm.load()
    f = tm.find_threats(arch, lib)
    assert {x.stride for x in f} == set("STRIDE")
    assert all(x.atlas and x.asi.startswith("ASI") for x in f)


def test_stride_per_element_table_is_respected():
    arch, lib = tm.load()
    for x in tm.find_threats(arch, lib):
        assert x.stride in tm.APPLIES[x.kind]


def test_protocol_specific_threats_only_where_the_protocol_is_used():
    arch, lib = tm.load()
    f = tm.find_threats(arch, lib)
    session = [x for x in f if "Session fixation" in x.title]
    assert session and all(x.element in ("sessions", "orch", "F8") for x in session)
    poison = [x for x in f if x.title.startswith("Shared context poisoned")]
    assert poison and {x.element for x in poison} <= {"ctx", "F6", "F7", "support", "refunds"} | {"F6", "F7"}


def test_scoring_uses_autonomy_and_boundary_crossing():
    t = {"impact": 4, "likelihood": 4}
    low = tm.score(t, {"autonomy": "low"}, 0)
    high = tm.score(t, {"autonomy": "high"}, 0)
    crossing = tm.score(t, {"autonomy": "high"}, 2)
    deep = tm.score(t, {"autonomy": "high"}, 2, delegation_depth=4)
    assert low < high < crossing < deep
    assert tm.score(t, None, 0) == 16.0


def test_refund_path_outranks_a_low_autonomy_tool():
    arch, lib = tm.load()
    f = tm.find_threats(arch, lib)
    best: dict[str, float] = {}
    for x in f:
        best[x.element] = max(best.get(x.element, 0), x.score)
    assert best["refunds"] > best["mcp_crm"]
    assert f == sorted(f, key=lambda x: -x.score)


def test_markdown_report_has_header_and_rows():
    arch, lib = tm.load()
    md = tm.to_markdown(tm.find_threats(arch, lib), 3)
    assert md.count("\n") == 4 and "ATLAS tactic" in md
