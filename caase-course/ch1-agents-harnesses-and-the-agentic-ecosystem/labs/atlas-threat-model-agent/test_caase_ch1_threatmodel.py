import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

tm = load_lab_module(__file__, "threatmodel")
HERE = Path(__file__).resolve().parent


def weak():
    return tm.load(HERE / "system.yaml")


def hard():
    return tm.load(HERE / "system-hardened.yaml")


def test_yaml_files_load_and_use_known_types_and_controls():
    assert len(weak()["components"]) == len(hard()["components"]) == 9


def test_every_finding_uses_valid_tactics_and_asi_ids():
    for f in tm.analyze(weak()):
        assert set(f.tactics) <= set(tm.COURSE_TACTICS)
        assert set(f.asi) <= set(tm.ASI_IDS)
        assert f.llm2026 and 1 <= f.likelihood <= 5 and 1 <= f.impact <= 5


def test_weak_design_covers_all_ten_asi_items_and_most_tactics():
    s = tm.summary(tm.analyze(weak()))
    assert s["asi_hit"] == tm.ASI_IDS
    assert len(s["tactics_hit"]) >= 9


def test_hardened_design_scores_much_lower():
    a, b = tm.summary(tm.analyze(weak())), tm.summary(tm.analyze(hard()))
    assert b["total_score"] < a["total_score"] * 0.6
    assert b["critical_or_high"] < a["critical_or_high"]
    assert b["max_score"] < a["max_score"]


def test_email_tool_is_the_top_risk_in_the_weak_design():
    top = tm.analyze(weak())[0]
    assert top.score >= 15 and top.level == "critical"
    assert top.component == "send_mail_tool" and top.score == 20  # reachable by injection, irreversible


def test_more_autonomy_and_irreversibility_raise_impact():
    base = {"side_effect": "external", "reversible": True, "privileges": 2, "data_sensitivity": 2}
    low = tm.impact_of(base, autonomy=1)
    assert tm.impact_of(base, autonomy=3) > low
    assert tm.impact_of({**base, "reversible": False}, autonomy=1) > low
    assert tm.impact_of({**base, "privileges": 5, "data_sensitivity": 5, "reversible": False}, 4) == 5


def test_controls_lower_likelihood_but_never_below_one():
    comp = {"untrusted_input": True, "controls": []}
    rule = tm.RULES["injection"]
    l0 = tm.likelihood_of(comp, rule)
    l1 = tm.likelihood_of({**comp, "controls": ["provenance"]}, rule)
    l3 = tm.likelihood_of({**comp, "controls": ["provenance", "schema_validation", "approval"]}, rule)
    assert l0 > l1 > l3 >= 1
    assert tm.likelihood_of({**comp, "controls": list(tm.KNOWN_CONTROLS)}, rule) >= 1


def test_missing_controls_are_listed_for_the_weak_design():
    f = next(x for x in tm.analyze(weak()) if x.component == "crm_mcp")
    assert {"signing", "sandbox", "allowlist"} <= set(f.missing)
    g = next(x for x in tm.analyze(hard()) if x.component == "crm_mcp")
    assert g.missing == []


def test_unknown_component_type_or_control_is_rejected():
    for body in ("name: x\ncomponents:\n  - {id: a, type: quantum_toaster}\n",
                 "name: x\ncomponents:\n  - {id: a, type: tool, controls: [magic]}\n",
                 "name: x\n"):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.yaml"
            p.write_text(body, encoding="utf-8")
            with pytest.raises(ValueError):
                tm.load(p)


def test_report_is_markdown_with_the_findings():
    text = tm.report(weak())
    assert text.startswith("# Threat model:") and "| critical |" in text and "ASI03" in text


def test_renamed_atlas_tactics_map_back_to_the_course_names():
    assert tm.RENAMED["AI Model Access"] in tm.COURSE_TACTICS
    assert tm.RENAMED["AI Attack Staging"] in tm.COURSE_TACTICS
