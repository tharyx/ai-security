from pathlib import Path

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "tmcode")
ROOT = Path(__file__).resolve().parent / "fixtures" / "shop"
M = t.build_model(ROOT)


def test_parses_python_and_javascript_comments():
    files = {i.file for i in M.items}
    assert "web_server.py" in files and "browser_ui.js" in files
    assert {i.tag for i in M.items} == {"exposes", "mitigates", "accepts", "connects"}


def test_multiword_threat_names_parse():
    threats = {i.threat for i in M.exposures()}
    assert {"Information Disclosure", "Denial of Service", "Spoofing"} <= threats


def test_status_mitigated_accepted_unmitigated():
    assert M.status("DMZ:WebServer", "Spoofing") == "mitigated"
    assert M.status("DMZ:WebServer", "Denial of Service") == "accepted"
    assert M.status("Internal:PaymentService", "Repudiation") == "UNMITIGATED"


def test_unmitigated_list_is_exactly_the_two_gaps():
    got = {(u.comp, u.threat) for u in M.unmitigated()}
    assert got == {("Internal:PaymentService", "Repudiation"), ("Internal:PaymentService", "Information Disclosure")}


def test_gate_fails_on_unmitigated_and_passes_when_fixed():
    assert t.gate(M) == 1
    fixed = t.Model(items=[i for i in M.items if i.tag != "exposes" or i.comp != "Internal:PaymentService"
                           or i.threat not in ("Repudiation", "Information Disclosure")])
    assert t.gate(fixed) == 0


def test_report_lists_unmitigated_and_evidence():
    r = t.report(M)
    assert "## Unmitigated exposures" in r and "card numbers in debug logs" in r
    assert "db_layer.py:" in r


def test_mermaid_has_zones_edges_and_red_class():
    m = t.mermaid(M)
    assert m.startswith("flowchart LR")
    assert 'subgraph Internal["Trust zone: Internal"]' in m
    assert '-->|"mutual TLS"|' in m
    assert "class Internal_PaymentService bad" in m


def test_malformed_and_non_stride_annotations_are_errors():
    items, errs = t.parse_text("# @exposes Web:App to Gremlins with bad\n# @mitigates oops\n# @fixes x\n", "x.py")
    assert len(items) == 1 and len(errs) == 3


def test_orphan_mitigation_is_reported():
    items, _ = t.parse_text("# @mitigates A:B against Spoofing with mfa\n", "o.py")
    m = t.Model(items=items)
    assert len(m.orphan_mitigations()) == 1 and "review" in t.report(m)
