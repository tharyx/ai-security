"""Tests for stride_mcp.py. Run: python -m pytest cmcpse-course/ch3-threat-modeling-mcp-architectures"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import yaml

from aisec_lab import load_lab_module

sm = load_lab_module(__file__, "stride_mcp")
HERE = Path(__file__).resolve().parent


def raw() -> dict:
    return yaml.safe_load((HERE / "mcp_architecture.yaml").read_text(encoding="utf-8"))


def test_sample_architecture_is_valid_and_has_the_required_shape():
    arch = sm.load_arch(HERE / "mcp_architecture.yaml")
    assert sm.validate(arch) == []
    names = [e["id"] for e in arch["elements"]]
    assert {"host", "files_server", "git_server", "db_server", "crm_server", "idp", "registry"} <= set(names)
    assert len([e for e in arch["elements"] if e["id"].endswith("_server")]) == 4  # 3 local + 1 remote OAuth


def test_validation_catches_bad_flows_and_zones():
    arch = raw()
    arch["flows"].append({"id": "F99", "source": "host", "target": "nowhere"})
    arch["flows"].append({"id": "F98", "source": "host_config", "target": "token_cache"})
    arch["elements"][0]["zone"] = "mars"
    problems = sm.validate(arch)
    assert any("nowhere" in p for p in problems)
    assert any("one end of every flow must be a process" in p for p in problems)
    assert any("unknown zone mars" in p for p in problems)


def test_crossings_follow_zones():
    arch = raw()
    cross = sm.crossings(arch)
    assert "F10" in cross        # host (desktop) -> crm (saas)
    assert "F4" in cross         # host (desktop) -> files server (local_servers)
    assert "F15" not in cross    # host_config -> host, same zone
    assert "F1" not in cross


def test_stride_per_element_respects_the_classic_table():
    findings = sm.find_threats(raw())
    for f in findings:
        assert f.stride in sm.STRIDE_PER_ELEMENT[f.kind], f
    # External entities only get S and R, data flows only T, I, D.
    assert {f.stride for f in findings if f.kind == "external_entity"} <= {"S", "R"}
    assert {f.stride for f in findings if f.kind == "data_flow"} <= {"T", "I", "D"}


def test_every_stride_letter_appears_for_the_sample():
    s = sm.summary(sm.find_threats(raw()))
    assert all(v > 0 for v in s["by_stride"].values()), s


def test_boundary_only_threat_needs_a_crossing_flow():
    findings = sm.find_threats(raw())
    inj = [f for f in findings if f.library_id == "MT-T03"]
    assert inj and all(f.crossing for f in inj)
    # F5 (files server -> host) crosses desktop/local_servers; a same-zone version must not get the finding.
    arch = raw()
    for e in arch["elements"]:
        e["zone"] = "desktop"
    assert not [f for f in sm.find_threats(arch) if f.library_id == "MT-T03"]


def test_existing_controls_mark_a_finding_mitigated_and_removing_them_reopens_it():
    arch = raw()
    base = {(f.element_id, f.library_id): f for f in sm.find_threats(arch)}
    assert base[("crm_server", "MT-E02")].status == "mitigated"      # scope_checks present
    assert base[("git_server", "MT-T04")].status == "open"
    arch2 = copy.deepcopy(arch)
    for e in arch2["elements"]:
        if e["id"] == "crm_server":
            e["controls"].remove("scope_checks")
    again = {(f.element_id, f.library_id): f for f in sm.find_threats(arch2)}
    assert again[("crm_server", "MT-E02")].status == "open"
    assert again[("crm_server", "MT-E02")].missing_controls == ["scope_checks"]


def test_mcp_specific_threats_are_found_where_expected():
    ids = {(f.element_id, f.library_id) for f in sm.find_threats(raw())}
    assert ("db_server", "MT-S03") in ids        # localhost HTTP server: DNS rebinding
    assert ("token_cache", "MT-I02") in ids      # plaintext token store
    assert ("host_config", "MT-T05") in ids      # command line in host config
    assert ("F14", "MT-T07") in ids              # registry metadata and package pointers
    assert ("host", "MT-T01") in ids             # tool poisoning reaches the host


def test_flows_inherit_assets_of_both_ends():
    f = {x.element_id: x for x in sm.find_threats(raw()) if x.kind == "data_flow"}
    assert "A6" in f["F11"].assets            # crm server -> host carries CRM data


def test_every_finding_has_owasp_or_asi_mapping_except_pure_availability():
    for f in sm.find_threats(raw()):
        if f.library_id != "MT-D02":
            assert f.owasp_mcp or f.asi, f.library_id


def test_outputs_are_parseable():
    arch = raw()
    findings = sm.find_threats(arch)
    assert json.loads(json.dumps([f.as_row() for f in findings]))
    csv_text = sm.to_csv(findings)
    assert csv_text.splitlines()[0].startswith("id,element_id")
    assert len(csv_text.splitlines()) == len(findings) + 1
    md = sm.to_markdown(findings, arch)
    assert "FND-001" in md and "(crosses boundary)" in md


def test_mermaid_has_subgraphs_and_dashed_crossings():
    m = sm.to_mermaid(raw())
    assert m.startswith("flowchart LR")
    assert m.count("subgraph") == 5
    assert "-.->|\"F10\"|" in m and "-->|\"F15\"|" in m


def test_cli_exit_codes(tmp_path=None):
    import tempfile
    assert sm.main([str(HERE / "mcp_architecture.yaml")]) == 0
    with tempfile.TemporaryDirectory() as d:
        bad = raw()
        bad["flows"][0]["target"] = "ghost"
        p = Path(d) / "bad.yaml"
        p.write_text(yaml.safe_dump(bad), encoding="utf-8")
        assert sm.main([str(p)]) == 2
