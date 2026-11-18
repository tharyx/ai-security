"""CERT-In audit tiering/findings and the risk -> control -> evidence matrix.

Assert impact: does missing evidence lead to a low tier? Can a high risk be called "proven"
when its control has stale or missing evidence? Does a risk with no control hide?

Run from the repository root:
    python -m pytest 08-ai-compliance -v
"""

import tempfile
from datetime import date
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

ci = load_lab_module(__file__, "certin_audit")
cm = load_lab_module(__file__, "compliance_matrix")
ev = load_lab_module(__file__, "evidence_checker")

AS_OF = date(2026, 11, 15)
FIX = Path(__file__).with_name("fixtures")
CONTROLS = ev.load(FIX / "controls.yaml")
RISKS = ev.load(FIX / "ai_risks.yaml")
AUDIT = yaml.safe_load((FIX / "certin_audit.yaml").read_text(encoding="utf-8"))
SYSTEMS = {s["system"]: s for s in AUDIT["systems"]}
FINDINGS = {f["id"]: f for f in AUDIT["findings"]}


def results(evidence_set):
    folder = FIX / f"evidence_{evidence_set}"
    return ev.check_evidence(CONTROLS, ev.load(folder / "index.yaml"), folder, AS_OF)


def tier_of(name):
    s = SYSTEMS[name]
    return ci.assess_tier(name, s["scores"], s.get("triggers"), s.get("self_assessed_tier"))


# ---------- CERT-In risk tiering --------------------------------------------------------

@pytest.mark.parametrize("composite,tier", [(8, 1), (12, 1), (13, 2), (19, 2), (20, 3), (26, 3), (27, 4), (32, 4)])
def test_composite_score_bands(composite, tier):
    assert ci.tier_from_composite(composite) == tier


@pytest.mark.parametrize("name,tier", [("internal-code-assistant", 1), ("support-chatbot", 2),
                                       ("cv-screening-provider", 3), ("payments-ops-agent", 3),
                                       ("grid-load-forecaster", 4)])
def test_fixture_systems_get_expected_tier(name, tier):
    assert tier_of(name).tier == tier


def test_missing_factor_fails_closed():
    scores = dict(SYSTEMS["support-chatbot"]["scores"])
    del scores["F7"]
    with pytest.raises(ValueError, match="F7"):
        ci.assess_tier("x", scores)


def test_scores_outside_one_to_four_are_rejected():
    scores = dict(SYSTEMS["support-chatbot"]["scores"], F1=0)
    with pytest.raises(ValueError):
        ci.assess_tier("x", scores)


def test_escalation_trigger_lifts_a_moderate_score():
    t = tier_of("payments-ops-agent")
    assert t.score_tier == 2 and t.tier == 3


def test_higher_of_auditor_and_self_assessed_tier_applies():
    t = tier_of("support-chatbot")  # organization said Tier 1, the scores say Tier 2
    assert t.tier == 2
    t = ci.assess_tier("x", SYSTEMS["internal-code-assistant"]["scores"], self_assessed_tier=3)
    assert t.tier == 3  # an organization may choose to be stricter


def test_tier_decides_mandatory_domains():
    assert tier_of("internal-code-assistant").mandatory_domains == ["8.1", "8.6"]
    assert len(tier_of("cv-screening-provider").mandatory_domains) == 9


# ---------- CERT-In domains joined with the evidence checker ------------------------------

def test_domain_status_uses_evidence_and_shows_design_gaps():
    vuln = ci.domain_evidence_status(CONTROLS, ev.control_status(results("vulnerable")))
    good = ci.domain_evidence_status(CONTROLS, ev.control_status(results("compliant")))
    assert vuln["8.6"] == "GAP" and good["8.6"] == "OK"
    assert vuln["8.4"] == good["8.4"] == "NO_CONTROL"  # no control maps to fairness: evidence cannot fix it


def test_tier_3_system_is_not_audit_ready_without_fairness_controls():
    t = tier_of("cv-screening-provider")
    good = ci.domain_evidence_status(CONTROLS, ev.control_status(results("compliant")))
    assert ci.audit_readiness(t, good) == ["8.4 ethics, bias and fairness: NO_CONTROL"]
    assert ci.audit_readiness(tier_of("internal-code-assistant"), good) == []


# ---------- findings, remediation and re-audit -------------------------------------------

def test_finding_owner_must_be_a_person():
    assert ci.check_finding(FINDINGS["AISAG-2026-001"]) == []
    assert any("named person" in p for p in ci.check_finding(FINDINGS["AISAG-2026-002"]))


def test_finding_without_root_cause_is_rejected():
    f = dict(FINDINGS["AISAG-2026-001"], cause="")
    assert "missing 'cause'" in ci.check_finding(f)


def test_moderate_finding_deadlines():
    plan = ci.remediation_plan("Moderate", date(2026, 11, 16))  # a Monday
    assert plan["cap_due"] == date(2026, 12, 28)  # 30 business days later
    assert plan["fix_due"] == date(2027, 1, 15)   # 60 days later


def test_low_finding_three_months_and_critical_escalates_now():
    assert ci.remediation_plan("Low", date(2026, 11, 30))["fix_due"] == date(2027, 2, 28)
    crit = ci.remediation_plan("Critical", date(2026, 11, 16))
    assert crit["escalate"].startswith("immediately") and crit["fix_due"] is None


def test_re_audit_triggers():
    two_critical = [{"severity": "Critical"}, {"severity": "Critical"}]
    assert ci.re_audit_required("Satisfactory with Reservations", two_critical)
    assert ci.re_audit_required("Unsatisfactory", [])
    assert not ci.re_audit_required("Requires Significant Improvement", [{"severity": "Critical"}])


# ---------- risk -> control -> evidence matrix ------------------------------------------

def verdicts(rows):
    return {r.risk_id: r.verdict for r in rows}


def test_compliant_evidence_proves_most_risks_but_not_design_gaps():
    v = verdicts(cm.build_matrix(RISKS, CONTROLS, results("compliant")))
    assert v["AR-01"] == "PROVEN" and v["AR-03"] == "PROVEN"
    assert v["AR-10"] == "NO_CONTROL"      # no control at all
    assert v["AR-09"] == "BROKEN_LINK"     # points to a control that does not exist


def test_vulnerable_evidence_leaves_high_risks_unproven():
    rows = cm.build_matrix(RISKS, CONTROLS, results("vulnerable"))
    v = verdicts(rows)
    assert v["AR-01"] == "UNPROVEN" and v["AR-03"] == "PARTIAL"
    s = cm.summary(rows)
    assert s["verdicts"].get("PROVEN", 0) == 0
    assert {"AR-01", "AR-03", "AR-07"} <= set(s["high_or_critical_not_proven"])


def test_matrix_rows_carry_owasp_2026_ids_and_framework_requirements():
    row = next(r for r in cm.build_matrix(RISKS, CONTROLS, results("compliant")) if r.risk_id == "AR-02")
    assert {"LLM03", "ASI03", "MCP02"} <= set(row.refs)
    access = next(lk for lk in row.links if lk.control == "CTL-ACCESS")
    assert "A.5.15 access control" in access.requirements["iso_27001"]


def test_matrix_is_sorted_critical_first_and_renders_markdown():
    rows = cm.build_matrix(RISKS, CONTROLS, results("compliant"))
    assert rows[0].rating == "Critical"
    md = cm.render_matrix_md(rows)
    assert md.splitlines()[0].startswith("| Risk | Rating | OWASP | Control | Evidence | EU AI Act")
    assert "**NO_CONTROL**" in md


def test_dashboard_renders_and_escapes_html():
    rows = cm.build_matrix([{"id": "AR-X", "risk": "<script>alert(1)</script>", "rating": "High",
                             "controls": []}], CONTROLS, results("compliant"))
    data = {"label": "test", "as_of": AS_OF, "inventory": [{"id": "AI-1", "name": "n", "tier": "high",
                                                             "status": "pilot"}],
            "policies": [{"Policy ID": "POL-1", "title": "t", "Owner": "o", "Next review": "2027-01-01",
                          "overdue": False}],
            "control_status": {"CTL-INV": "OK"}, "coverage": {}, "matrix": rows}
    page = cm.render_dashboard_html(data)
    assert "<script>alert" not in page and "&lt;script&gt;" in page
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "dashboard.md"
        out.write_text(cm.render_dashboard_md(data), encoding="utf-8")
        assert "High/critical risks not proven | AR-X" in out.read_text(encoding="utf-8")


def test_policy_header_parser_reads_the_policy_pack():
    text = (Path(__file__).resolve().parents[2] / "07-ai-governance" / "policies" /
            "03-ai-model-approval-policy.md").read_text(encoding="utf-8")
    h = cm.parse_policy_header(text)
    assert h["Policy ID"] == "POL-AI-03" and h["Next review"] == "2027-11-01"
