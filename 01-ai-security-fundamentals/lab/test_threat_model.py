"""Tests for the threat-model-as-code analyzer.

Each rule must fire on the vulnerable design and stay quiet on the secure design.
Removing a control from the secure design must bring the finding back - that proves
the control is what fixed it (the same idea as switching off a defense layer).

Run from the repository root:
    python -m pytest 01-ai-security-fundamentals -v
"""

from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from aisec_lab import load_lab_module

tm = load_lab_module(__file__, "threat_model")

DESIGNS = Path(__file__).parent / "designs"
TODAY = date(2026, 11, 18)


def vulnerable():
    return tm.load_design(DESIGNS / "vulnerable_design.yaml")


def secure():
    return tm.load_design(DESIGNS / "secure_design.yaml")


def open_rules(design, today=TODAY):
    return {(f.rule, f.target) for f in tm.analyze(design, today) if f.status == "open"}


def flow(design, fid):
    return next(f for f in design.flows if f.id == fid)


# ---------- Part 1: every rule fires on the vulnerable design ---------------------------

@pytest.mark.parametrize("rule", list(tm.RULES))
def test_vulnerable_design_triggers_every_rule(rule):
    assert any(r == rule for r, _ in open_rules(vulnerable()))


def test_vulnerable_design_has_the_lethal_trifecta_with_all_three_channels():
    tri = tm.trifecta(vulnerable(), "llm")
    assert tri["private"] and tri["untrusted"] == ["inbound_email"]
    assert set(tri["channels"]) == {"send_email", "http_fetch", "web_ui:markdown-images"}


def test_vulnerable_design_fails_the_ci_gate():
    assert tm.main(["threat_model.py", str(DESIGNS / "vulnerable_design.yaml")]) == 1


# ---------- Part 2: the secure design is clean ------------------------------------------

def test_secure_design_has_no_open_findings():
    assert open_rules(secure()) == set()


def test_secure_design_passes_the_ci_gate():
    assert tm.main(["threat_model.py", str(DESIGNS / "secure_design.yaml")]) == 0


def test_secure_model_is_still_tainted_but_has_no_exfiltration_channel():
    tri = tm.trifecta(secure(), "llm")
    assert tri["untrusted"] == ["inbound_email"]  # taint is accepted ...
    assert tri["private"]                         # ... private data is needed ...
    assert tri["channels"] == []                  # ... so the exit leg was removed.


# ---------- Part 3: remove one control -> the finding comes back ------------------------

@pytest.mark.parametrize("fid, control, rule", [
    ("F05", "acl_filter", "RAG-001"),
    ("F05", "tenant_filter", "RAG-001"),
    ("F07", "tool_authz", None),             # human_approval still gates it ...
    ("F07", "schema_validation", "OUT-001"),
    ("F07", "audit_log", "REP-001"),
    ("F12", "output_encoding", "OUT-001"),
    ("F04", "dpa", "DATA-001"),
    ("F13", "redaction", "DATA-001"),
    ("F01", "authn", "AUTH-001"),
    ("F01", "rate_limit", "DOS-001"),
])
def test_removing_a_control_reopens_its_finding(fid, control, rule):
    d = secure()
    flow(d, fid).controls.remove(control)
    found = open_rules(d)
    if rule is None:
        assert not any(r == "TB-001" for r, _ in found)
    else:
        assert (rule, fid) in found


def test_removing_both_hard_gates_reopens_tb001():
    d = secure()
    for c in ("tool_authz", "human_approval"):
        flow(d, "F07").controls.remove(c)
    assert ("TB-001", "F07") in open_rules(d)


def test_removing_the_url_allowlist_reopens_the_trifecta_via_markdown_images():
    d = secure()
    flow(d, "F12").controls.remove("url_allowlist")
    assert ("TRI-001", "llm") in open_rules(d)
    assert tm.trifecta(d, "llm")["channels"] == ["web_ui:markdown-images"]


def test_adding_an_email_tool_to_the_secure_model_reopens_the_trifecta():
    d = secure()
    d.components.append(tm.Component(id="send_email", type="tool", zone="app_backend",
                                     capabilities=["external_comms"]))
    d.flows.append(tm.Flow.model_validate({
        "id": "F99", "from": "llm", "to": "send_email", "data": "tool call", "identity": "user",
        "controls": ["tls", "schema_validation", "tool_authz", "audit_log"]}))
    findings = {(f.rule, f.target): f for f in tm.analyze(d, TODAY)}
    assert findings[("TRI-001", "llm")].severity == "critical"  # perfect tool hygiene, still exfil


def test_human_approval_only_lowers_trifecta_likelihood():
    d = secure()
    d.components.append(tm.Component(id="send_email", type="tool", zone="app_backend",
                                     capabilities=["external_comms"]))
    d.flows.append(tm.Flow.model_validate({
        "id": "F99", "from": "llm", "to": "send_email", "data": "tool call", "identity": "user",
        "controls": ["tls", "schema_validation", "tool_authz", "human_approval", "audit_log"]}))
    tri = next(f for f in tm.analyze(d, TODAY) if f.rule == "TRI-001")
    assert tri.severity == "high"  # gated, not gone


# ---------- Part 4: soft controls do not wash out taint ---------------------------------

def test_soft_controls_do_not_remove_taint_or_fix_tb001():
    d = vulnerable()
    flow(d, "F03").controls += ["spotlighting", "injection_detection", "content_filter"]
    flow(d, "F07").controls += ["spotlighting", "injection_detection"]
    found = open_rules(d)
    assert ("TB-001", "F07") in found
    assert ("TRI-001", "llm") in found
    assert "inbound_email" in tm.taint_origins(d)["llm"]


def test_a_soft_control_alone_does_not_count_as_a_boundary_rule():
    found = open_rules(vulnerable())
    assert ("TB-002", "F03") in found  # only system_prompt_rule on the internet -> api hop


# ---------- Part 5: schema, scoring, acceptance and STRIDE ------------------------------

def test_unknown_control_name_is_rejected_not_ignored():
    with pytest.raises(ValidationError):
        tm.Flow.model_validate({"id": "X", "from": "a", "to": "b", "data": "d",
                                "controls": ["acl-filter"]})  # typo


def test_flow_to_an_unknown_component_is_rejected():
    raw = secure().model_dump(by_alias=True)
    raw["flows"][0]["to"] = "ghost"
    with pytest.raises(ValidationError):
        tm.Design.model_validate(raw)


@pytest.mark.parametrize("likelihood, impact, expected", [
    (5, 5, "critical"), (4, 5, "critical"), (4, 4, "high"), (3, 4, "high"),
    (3, 3, "medium"), (2, 3, "medium"), (1, 5, "low"),
])
def test_risk_score_bands(likelihood, impact, expected):
    assert tm.severity(likelihood, impact) == expected


def test_risk_acceptance_expires():
    assert ("DOS-001", "F03") not in open_rules(secure(), today=date(2027, 6, 30))
    assert ("DOS-001", "F03") in open_rules(secure(), today=date(2027, 7, 1))


def test_stride_candidates_cover_every_element_and_flow():
    d = secure()
    threats = tm.stride_candidates(d)
    elements = {t.element for t in threats}
    assert {c.id for c in d.components} | {f.id for f in d.flows} <= elements
    model_cats = {t.category for t in threats if t.element == "llm"}
    assert model_cats == set("STRIDE")


def test_every_rule_traces_to_a_testable_requirement():
    assert set(tm.REQUIREMENTS) == set(tm.RULES)
    for req_id, text, verify in tm.REQUIREMENTS.values():
        assert req_id.startswith("REQ-")
        assert "MUST" in text  # requirement language, not "should try to"
        assert verify.startswith(("test:", "CI:"))


def test_requirements_are_derived_only_from_open_findings():
    vuln_reqs = {r[0] for r in tm.requirements(vulnerable(), TODAY)}
    assert {"REQ-RAG-01", "REQ-TOOL-01", "REQ-ARCH-01"} <= vuln_reqs
    assert tm.requirements(secure(), TODAY) == []  # the accepted risk does not create a req


def test_secure_design_has_more_stride_candidates_with_mapped_controls():
    def covered(d):
        return sum(bool(t.controls) for t in tm.stride_candidates(d))
    assert covered(secure()) > covered(vulnerable())
