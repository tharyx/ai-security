import json
from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "sbscan")
FIX = Path(__file__).resolve().parent / "fixtures"
CFG = json.loads((FIX / "triage.json").read_text())
TODAY = date(2026, 11, 19)


def test_xml_parse_reads_type_rank_class_method_and_line():
    bugs = s.parse(FIX / "spotbugsXml.xml")
    assert len(bugs) == 10
    sql = next(b for b in bugs if b.type == "SQL_INJECTION_JDBC" and "UserDao" in b.cls)
    assert (sql.rank, sql.method, sql.line, sql.cwe) == (3, "findByName", 42, 89)
    assert any(b.method == "<clinit>" for b in bugs)       # &lt;clinit&gt; is unescaped by the XML parser


def test_sarif_and_xml_agree():
    x = {(b.type, b.cls, b.line, b.cwe) for b in s.parse(FIX / "spotbugsXml.xml") if b.cwe}
    r = {(b.type, b.cls, b.line, b.cwe) for b in s.parse(FIX / "results.sarif") if b.cwe}
    assert x == r


def test_sarif_cwe_comes_from_rule_tags():
    b = next(b for b in s.parse(FIX / "results.sarif") if b.type == "XSS_SERVLET")
    assert b.cwe == 79


def test_triage_drops_test_code_and_non_security_categories():
    active, dropped = s.triage(s.parse(FIX / "spotbugsXml.xml"), CFG, TODAY)
    why = {b.type: w for b, w in dropped}
    assert "excluded path" in why["SQL_INJECTION_JDBC"]
    assert "category I18N" in why["DM_DEFAULT_ENCODING"] and "category CORRECTNESS" in why["NP_NULL_ON_SOME_PATH"]
    assert all(b.category == "SECURITY" for b in active)


def test_decisions_apply_until_they_expire():
    active, dropped = s.triage(s.parse(FIX / "spotbugsXml.xml"), CFG, TODAY)
    assert "HARD_CODE_PASSWORD" in {b.type for b, _ in dropped}                    # valid false-positive decision
    expired = next(b for b in active if b.type == "PREDICTABLE_RANDOM")
    assert expired.status == "expired-decision" and "re-review" in expired.reason   # accepted risk lapsed
    active2, dropped2 = s.triage(s.parse(FIX / "spotbugsXml.xml"), CFG, date(2026, 1, 1))
    assert "PREDICTABLE_RANDOM" in {b.type for b, _ in dropped2}


def test_active_findings_sorted_by_rank_and_labelled():
    active, _ = s.triage(s.parse(FIX / "spotbugsXml.xml"), CFG, TODAY)
    assert [b.type for b in active][:2] == ["COMMAND_INJECTION", "SQL_INJECTION_JDBC"]
    assert s.label(2) == "scariest" and s.label(9) == "scary" and s.label(12) == "troubling" and s.label(18) == "of concern"


def test_gate_depends_on_rank_threshold():
    active, _ = s.triage(s.parse(FIX / "spotbugsXml.xml"), CFG, TODAY)
    assert s.gate(active, 9) == 1 and s.gate(active, 1) == 0
    assert s.gate([b for b in active if b.rank > 9], 9) == 0


def test_grouping_by_cwe_and_fingerprint_is_line_independent():
    active, _ = s.triage(s.parse(FIX / "spotbugsXml.xml"), CFG, TODAY)
    groups = s.group_by_cwe(active)
    assert "CWE-89 SQL Injection" in groups and len(groups["CWE-89 SQL Injection"]) == 1
    b = active[0]
    moved = s.Bug(b.type, b.category, b.rank, b.cls, b.method, b.path, b.line + 100, b.cwe)
    assert moved.key == b.key
