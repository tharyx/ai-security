"""Tests for tm_tool.py. Run: python -m pytest caisp-course/ch5-threat-modeling-ai-systems"""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

from aisec_lab import load_lab_module

tm = load_lab_module(__file__, "tm_tool")
HERE = Path(__file__).resolve().parent


def raw_dfd() -> dict:
    return yaml.safe_load((HERE / "dfd.yaml").read_text(encoding="utf-8"))


def dfd_from(raw: dict):
    return tm.DFD.model_validate(raw)


def test_sample_dfd_is_valid():
    dfd = tm.load_dfd(HERE / "dfd.yaml")
    assert [i for i in tm.validate_dfd(dfd) if i.level == "error"] == []


def test_unknown_flow_endpoint_is_an_error():
    raw = raw_dfd()
    raw["flows"].append({"id": "F99", "source": "orchestrator", "target": "ghost"})
    errors = [i.message for i in tm.validate_dfd(dfd_from(raw)) if i.level == "error"]
    assert any("unknown target 'ghost'" in m for m in errors)


def test_flow_between_entity_and_store_is_an_error():
    raw = raw_dfd()
    raw["flows"].append({"id": "F98", "source": "user", "target": "vdb"})
    errors = [i.message for i in tm.validate_dfd(dfd_from(raw)) if i.level == "error"]
    assert any("no process end" in m for m in errors)


def test_duplicate_ids_and_unknown_zone_and_orphan():
    raw = raw_dfd()
    raw["elements"].append({"id": "user", "type": "process", "zone": "mars"})
    raw["elements"].append({"id": "lonely", "type": "process", "zone": "app"})
    messages = [(i.level, i.message) for i in tm.validate_dfd(dfd_from(raw))]
    assert ("error", "duplicate id: user") in messages
    assert any("unknown zone 'mars'" in m for _, m in messages)
    assert ("warning", "element lonely has no data flow (orphan)") in messages


def test_stride_per_element_letters():
    dfd = tm.load_dfd(HERE / "dfd.yaml")
    register = tm.build_register(dfd, tm.load_library())
    allowed = tm.STRIDE_PER_ELEMENT
    for t in register:
        assert t.stride in allowed[t.subject_kind]
    entity_letters = {t.stride for t in register if t.subject_kind == "external_entity"}
    assert entity_letters <= {"S", "R"}
    flow_letters = {t.stride for t in register if t.subject_kind == "data_flow"}
    assert flow_letters <= {"T", "I", "D"}
    process_letters = {t.stride for t in register if t.subject_kind == "process"}
    assert process_letters == set("STRIDE")


def test_threats_are_enriched_with_owasp_atlas_and_biml():
    dfd = tm.load_dfd(HERE / "dfd.yaml")
    register = tm.build_register(dfd, tm.load_library())
    injection = [t for t in register if t.library_id == "TL-04"]
    assert injection, "indirect prompt injection must be found"
    assert all("LLM01 Prompt Injection" in t.owasp_llm for t in injection)
    assert all("LLM Prompt Injection" in t.atlas for t in injection)
    assert all(t.biml.get("component") for t in injection)
    # F6 carries retrieved text, so it must be flagged
    assert any("F6" in t.subject for t in injection)


def test_generic_fallback_when_library_has_no_match():
    dfd = tm.load_dfd(HERE / "dfd.yaml")
    empty = tm.ThreatLibrary(entries=[])
    register = tm.build_register(dfd, empty)
    assert register and all(t.library_id == "GENERIC" for t in register)


def test_owasp_rating_math():
    # 0-3 low, 3-6 medium, 6-9 high; (HIGH, HIGH) is critical
    assert tm.level(2.9) == "LOW" and tm.level(3) == "MEDIUM" and tm.level(6) == "HIGH"
    r = tm.rate([9, 9, 9, 9], [9, 9, 9, 9], 9, 9)
    assert r["severity"] == "CRITICAL" and r["likelihood"] == 9 and r["impact"] == 9
    assert tm.rate(1, 1, 1, 1)["severity"] == "NOTE"
    # high likelihood, low impact is only MEDIUM
    assert tm.rate(8, 8, 1, 1)["severity"] == "MEDIUM"
    # low likelihood, high impact is MEDIUM too
    assert tm.rate(1, 1, 8, 8)["severity"] == "MEDIUM"


def test_every_matrix_cell_exists():
    for lk in ("LOW", "MEDIUM", "HIGH"):
        for im in ("LOW", "MEDIUM", "HIGH"):
            assert tm.SEVERITY_MATRIX[(lk, im)] in tm.SEVERITY_ORDER


def test_control_lowers_residual_risk_and_changes_status():
    raw = raw_dfd()
    base = tm.build_register(dfd_from(raw), tm.load_library())
    tool_before = [t for t in base if t.library_id == "TL-17" and t.subject.startswith("ticket_tool")][0]
    assert tool_before.status == "open"

    hardened = copy.deepcopy(raw)
    for e in hardened["elements"]:
        if e["id"] == "ticket_tool":
            e["controls"] = ["tool_authz", "human_approval", "authn"]
    after = tm.build_register(dfd_from(hardened), tm.load_library())
    tool_after = [t for t in after if t.library_id == "TL-17" and t.subject.startswith("ticket_tool")][0]
    assert tool_after.status == "controlled"
    order = tm.SEVERITY_ORDER
    assert order.index(tool_after.residual_severity) < order.index(tool_before.residual_severity)
    assert tool_after.severity == tool_before.severity  # inherent stays the same


def test_register_is_sorted_by_residual_severity():
    register = tm.build_register(tm.load_dfd(HERE / "dfd.yaml"), tm.load_library())
    ranks = [tm.SEVERITY_ORDER.index(t.residual_severity) for t in register]
    assert ranks == sorted(ranks, reverse=True)


def test_sample_system_has_blocking_findings_and_hardening_removes_some():
    raw = raw_dfd()
    lib = tm.load_library()
    before = tm.blocking(tm.build_register(dfd_from(raw), lib))
    assert before, "the sample design should have open high/critical threats"
    for e in raw["elements"]:
        if e["id"] in ("orchestrator", "ticket_tool"):
            e["controls"] = sorted(set(e["controls"]) | {"tool_authz", "human_approval", "schema_validation",
                                                         "rate_limit", "token_budget", "redaction"})
    after = tm.blocking(tm.build_register(dfd_from(raw), lib))
    assert len(after) < len(before)


def test_asset_value_raises_business_impact():
    raw = raw_dfd()
    lib = tm.load_library()
    low = copy.deepcopy(raw)
    for a in low["assets"]:
        a["value"] = 0
    high = copy.deepcopy(raw)
    for a in high["assets"]:
        a["value"] = 9
    t_low = next(t for t in tm.build_register(dfd_from(low), lib) if t.library_id == "TL-10")
    t_high = next(t for t in tm.build_register(dfd_from(high), lib) if t.library_id == "TL-10")
    assert t_high.impact > t_low.impact


def test_mermaid_has_zones_nodes_and_flows():
    text = tm.to_mermaid(tm.load_dfd(HERE / "dfd.yaml"))
    assert text.startswith("flowchart LR")
    assert text.count("subgraph") == 4 and text.count("  end") == 4
    assert 'vdb[("Vector database")]' in text
    assert 'orchestrator(("Chat API and orchestrator"))' in text
    assert "F6: context chunks" in text


def test_outputs_json_csv_table():
    register = tm.build_register(tm.load_dfd(HERE / "dfd.yaml"), tm.load_library())
    assert tm.to_json(register).startswith("[")
    csv_text = tm.to_csv(register)
    assert csv_text.splitlines()[0].startswith("id,subject,stride")
    assert len(csv_text.splitlines()) == len(register) + 1
    assert "THREAT / WHERE" in tm.to_table(register, top=5)


def test_library_entries_are_valid_and_unique():
    lib = tm.load_library()
    ids = [e.id for e in lib.entries]
    assert len(ids) == len(set(ids)) and len(ids) >= 20
    letters = {e.stride for e in lib.entries}
    assert letters == set("STRIDE")  # every STRIDE class has at least one entry
    assert all(e.owasp_llm and e.atlas and e.biml for e in lib.entries)


def test_cli_exit_codes():
    assert tm.main([str(HERE / "dfd.yaml")]) == 1          # open high findings
    assert tm.main([str(HERE / "dfd.yaml"), "--mermaid"]) == 0
