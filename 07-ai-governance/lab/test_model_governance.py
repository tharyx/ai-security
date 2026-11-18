"""Model documentation, model approval, incident triage and policy-pack tests.

Assert impact: can an unpinned or swapped model deploy? Does an ongoing leak get SEV1 and
start the legal clocks? Can a policy without evidence pass? Not just wording.

Run from the repository root:
    python -m pytest 07-ai-governance -v
"""

import copy
import tempfile
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from aisec_lab import load_lab_module

doc = load_lab_module(__file__, "doc_validator")
appr = load_lab_module(__file__, "model_approval")
tri = load_lab_module(__file__, "incident_triage")
lint = load_lab_module(__file__, "policy_lint")
vuln = load_lab_module(__file__, "vulnerable_register")

AS_OF = date(2026, 11, 15)
FIX = Path(__file__).with_name("fixtures")
POLICIES = Path(__file__).resolve().parents[1] / "policies"


def load(name):
    return yaml.safe_load((FIX / name).read_text(encoding="utf-8"))


GOOD_DOCS, BAD_DOCS = load("documentation_governed.yaml"), load("documentation_vulnerable.yaml")
REQUESTS = {r["request_id"]: r for r in load("model_requests.yaml")}
INCIDENTS = {i["id"]: i for i in load("incidents.yaml")}


def codes(findings):
    return {f.code for f in findings}


# ---------- documentation: model cards, datasheets, disclosure ----------------------------

def test_governed_documentation_pack_is_clean():
    assert doc.validate_pack(GOOD_DOCS, AS_OF) == []


def test_vulnerable_pack_finds_every_documentation_failure():
    found = codes(doc.validate_pack(BAD_DOCS, AS_OF))
    expected = {f"DOC-0{i}" for i in range(1, 9)} | {f"DS-0{i}" for i in range(1, 6)} | {"TR-01", "TR-02", "TR-03"}
    assert expected <= found


def test_card_without_security_eval_is_flagged():
    card = copy.deepcopy(GOOD_DOCS["model_cards"][0])
    card["evaluation"] = [e for e in card["evaluation"] if e["type"] != "security"]
    assert "DOC-02" in codes(doc.validate_model_card(card, AS_OF))


def test_lower_is_better_metric_is_judged_the_right_way():
    card = copy.deepcopy(GOOD_DOCS["model_cards"][0])
    gap = next(e for e in card["evaluation"] if e["name"] == "gender_gap_in_summary_tone")
    gap["result"] = 0.09  # a bigger gap is worse
    assert any("gender_gap" in f.message for f in doc.validate_model_card(card, AS_OF) if f.code == "DOC-03")


def test_no_known_limitations_is_not_an_answer():
    card = copy.deepcopy(GOOD_DOCS["model_cards"][0])
    card["limitations"] = ["No known limitations"]
    assert "DOC-06" in codes(doc.validate_model_card(card, AS_OF))


def test_labels_must_follow_data_into_embeddings():
    sheet = copy.deepcopy(GOOD_DOCS["datasheets"][0])
    sheet["derived_artifacts"].append({"name": "vector-index", "classification": "internal"})
    assert "DS-04" in codes(doc.validate_datasheet(sheet))


def test_card_goes_stale_with_time():
    card = GOOD_DOCS["model_cards"][0]
    assert "DOC-07" in codes(doc.validate_model_card(card, AS_OF + timedelta(days=200)))


# ---------- model approval and the deployment check ---------------------------------------

def test_naive_approval_approves_the_unpinned_self_approved_request():
    assert vuln.naive_model_approval(REQUESTS["MAR-002"]) == "APPROVED"


def test_gates_reject_the_unpinned_self_approved_request():
    d = appr.assess_request(REQUESTS["MAR-002"], AS_OF)
    assert d.decision == "REJECTED"
    assert {"MA-01", "MA-02", "MA-03", "MA-04", "MA-05", "MA-06", "MA-07", "MA-08"} <= {c for c, _ in d.findings}


def test_good_requests_are_approved_with_tier_based_expiry():
    high = appr.assess_request(REQUESTS["MAR-001"], AS_OF)
    medium = appr.assess_request(REQUESTS["MAR-003"], AS_OF)
    assert (high.decision, medium.decision) == ("APPROVED", "APPROVED")
    assert high.valid_until == AS_OF + timedelta(days=180) and medium.valid_until == AS_OF + timedelta(days=365)


def test_requester_cannot_be_the_security_approver():
    req = copy.deepcopy(REQUESTS["MAR-001"])
    req["approvals"] = [a if a["role"] != "security" else {"role": "security", "name": "a.rao"}
                        for a in req["approvals"]]
    d = appr.assess_request(req, AS_OF)
    assert d.decision == "REJECTED" and "MA-07" in {c for c, _ in d.findings}


def test_unknown_tier_is_treated_as_critical():
    req = copy.deepcopy(REQUESTS["MAR-003"])
    req["tier"] = "probably-fine"
    d = appr.assess_request(req, AS_OF)
    assert d.tier == "critical" and d.decision == "REJECTED"


def test_silent_model_swap_cannot_deploy():
    registry = [appr.assess_request(r, AS_OF) for r in REQUESTS.values()]
    good = REQUESTS["MAR-001"]["artifact_sha256"]
    swapped = "0" * 64
    assert appr.can_deploy(registry, "AI-002", "cv-summarizer", good, AS_OF)[0]
    ok, why = appr.can_deploy(registry, "AI-002", "cv-summarizer", swapped, AS_OF)
    assert not ok and "hash differs" in why
    assert vuln.naive_can_deploy_model({"cv-summarizer"}, "cv-summarizer")  # the name-only check passes


def test_approval_expires():
    registry = [appr.assess_request(REQUESTS["MAR-001"], AS_OF)]
    sha = REQUESTS["MAR-001"]["artifact_sha256"]
    ok, why = appr.can_deploy(registry, "AI-002", "cv-summarizer", sha, AS_OF + timedelta(days=181))
    assert not ok and "expired" in why


def test_approval_is_per_system():
    registry = [appr.assess_request(REQUESTS["MAR-001"], AS_OF)]
    sha = REQUESTS["MAR-001"]["artifact_sha256"]
    assert not appr.can_deploy(registry, "AI-009", "cv-summarizer", sha, AS_OF)[0]


# ---------- incident triage ----------------------------------------------------------------

@pytest.mark.parametrize("iid,severity", [("INC-01", "SEV1"), ("INC-02", "SEV2"), ("INC-03", "SEV3"),
                                          ("INC-04", "SEV4"), ("INC-05", "SEV2")])
def test_severity_follows_impact(iid, severity):
    assert tri.triage(INCIDENTS[iid]).severity == severity


def test_naive_triage_treats_an_ongoing_injection_leak_as_a_quality_bug():
    assert vuln.naive_incident_severity(INCIDENTS["INC-01"]) == "SEV4"


def test_ai_involvement_alone_does_not_change_severity():
    a = copy.deepcopy(INCIDENTS["INC-03"])
    b = copy.deepcopy(a)
    b["ai_component"] = True
    assert tri.triage(a).severity == tri.triage(b).severity


def test_ongoing_leak_stays_sev1_until_containment_is_verified():
    inc = copy.deepcopy(INCIDENTS["INC-01"])
    inc["containment_requested"] = True
    assert tri.triage(inc).severity == "SEV1" and not tri.can_downgrade(inc)
    inc["containment_verified"] = True
    assert tri.triage(inc).severity == "SEV2" and tri.can_downgrade(inc)


def test_triage_produces_the_flags_that_start_module_08_clocks():
    flags = tri.triage(INCIDENTS["INC-01"]).clock_flags
    assert flags["personal_data_breach"] and flags["eu_personal_data"] and flags["india_personal_data"]
    assert flags["india_reportable_cyber_incident"]
    hr = tri.triage(INCIDENTS["INC-02"]).clock_flags
    assert hr["eu_high_risk_provider"] and hr["eu_serious_incident"]


def test_near_miss_starts_no_clock_and_no_containment():
    t = tri.triage(INCIDENTS["INC-04"])
    assert not any(t.clock_flags.values()) and t.actions[0].startswith("Near miss")


def test_triage_maps_to_owasp_2026_and_agentic_ids():
    t = tri.triage(INCIDENTS["INC-01"])
    assert t.owasp_llm_2026 == ["LLM01"] and t.owasp_agentic == ["ASI01"]


def test_unknown_vector_fails_closed():
    with pytest.raises(ValueError):
        tri.triage({"id": "X", "vector": "something-new"})


# ---------- policy pack ----------------------------------------------------------------------

def test_policy_pack_has_seven_clean_policies():
    results = lint.lint_folder(POLICIES, AS_OF)
    assert len(results) == 7
    assert {name: [f.code for f in fs] for name, fs in results.items() if fs} == {}


def test_every_policy_requirement_says_how_it_is_checked():
    for p in sorted(POLICIES.glob("[0-9][0-9]-*.md")):
        reqs = lint.requirements(p.read_text(encoding="utf-8"))
        assert len(reqs) >= 8 and all(check for _, _, check in reqs), p.name


def test_linter_catches_a_broken_policy():
    text = (POLICIES / "01-ai-acceptable-use-policy.md").read_text(encoding="utf-8")
    broken = (text.replace("| 2027-05-01 |", "| 2026-01-01 |")
                  .replace("## 5. Exceptions", "## 5. Waivers")
                  .replace("Training completion report (target 95%)", "TBD"))
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "01-broken.md").write_text(broken, encoding="utf-8")
        found = {f.code for f in lint.lint_folder(tmp, AS_OF)["01-broken.md"]}
    assert {"POL-01", "POL-04", "POL-05"} <= found
