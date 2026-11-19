import json
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

HERE = Path(__file__).resolve().parent
tm = load_lab_module(__file__, "pytmlite")
shop = load_lab_module(__file__, "model_shop")


def keys(model):
    return {f.key for f in model.process()}


def test_first_draft_finds_cleartext_login_and_unencrypted_pii():
    found = keys(shop.build(secure=False))
    assert ("DF01", "Login and browse") in found
    assert ("DF02", "Login and browse") in found
    assert ("DS01", "Orders DB") in found


def test_internal_flows_do_not_trigger_boundary_rule():
    found = keys(shop.build(secure=False))
    assert ("DF01", "SQL query") not in found  # same boundary and encrypted


def test_untrusted_input_is_derived_from_the_dataflows():
    draft = shop.build(secure=False)
    found = keys(draft)
    assert ("INP01", "Web App") in found          # fed by the Internet actor
    assert ("INP01", "Orders API") not in found   # fed only by the DMZ web app and it sanitizes


def test_gate_fails_on_draft_and_passes_after_controls_are_added():
    assert tm.gate(shop.build(secure=False).process()) == 1
    fixed = shop.build(secure=True)
    assert fixed.process() == [] and tm.gate(fixed.findings) == 0


def test_accepted_high_findings_do_not_fail_the_gate():
    findings = shop.build(secure=False).process()
    accepted = {f.key for f in findings if f.severity == "High"}
    assert tm.gate(findings, accepted=accepted) == 0
    assert tm.gate(findings, accepted=accepted, fail_on="Medium") == 1


def test_declarative_json_model_gives_the_same_findings_as_python_model():
    as_code = tm.load_model(HERE / "fixtures" / "shop_model.json")
    assert keys(as_code) == keys(shop.build(secure=False))


def test_findings_become_security_requirements():
    draft = shop.build(secure=False)
    draft.process()
    reqs = draft.requirements()
    assert reqs["REQ-TLS-01"] == ["HTML page", "Login and browse"]
    assert "REQ-AUTHZ-01" in reqs and "REQ-DATA-01" in reqs


def test_custom_templates_change_the_report_not_the_model():
    draft = shop.build(secure=False)
    summary = draft.report((HERE / "templates" / "exec_summary.md").read_text(encoding="utf-8"))
    assert "High-severity findings: **8** of 13." in summary and "Do not release" in summary
    assert "- [ ] REQ-TLS-01 applies to: HTML page, Login and browse" in summary
    csv = draft.report((HERE / "templates" / "findings.csv").read_text(encoding="utf-8")).splitlines()
    assert csv[0] == "sid,severity,stride,target,requirement" and len(csv) == 14
    fixed = shop.build(secure=True)
    assert "No high findings" in fixed.report((HERE / "templates" / "exec_summary.md").read_text(encoding="utf-8"))


def test_dfd_dot_and_plantuml_sequence_are_generated():
    draft = shop.build(secure=False)
    dot = draft.dfd()
    assert dot.startswith('digraph "Shop"') and 'label="Internet"; style=bold' in dot
    assert 'Web_App -> Orders_API [label="Place order (enc)"]' in dot
    seq = draft.seq()
    assert seq.splitlines()[0] == "@startuml" and seq.splitlines()[-1] == "@enduml"
    assert 'database "Orders DB" as Orders_DB' in seq


def test_typo_in_attribute_name_is_rejected():
    with tm.TM("t"):
        with pytest.raises(AttributeError):
            tm.Server("x", sanitisesInput=True)  # British spelling: not a known attribute


def test_model_check_reports_orphans():
    with tm.TM("t") as t:
        tm.Server("lonely")
    assert t.check() == ["element with no data flow: lonely"]


def test_threat_library_conditions_cannot_run_code():
    evil = [{"SID": "X", "target": ["Process"], "condition": "__import__('os').system('echo hi')",
             "stride": "Tampering", "severity": "High", "description": "d", "mitigation": "m",
             "requirement": "R"}]
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "lib.json"
        p.write_text(json.dumps(evil), encoding="utf-8")
        lib = tm.load_library(p)
    with pytest.raises(ValueError):
        shop.build(secure=False).process(lib)
