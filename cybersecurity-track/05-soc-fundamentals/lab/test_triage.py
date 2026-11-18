"""Tests for the alert triage simulator, including tricky benign cases.

Run from the repository root:
    python -m pytest cybersecurity-track/05-soc-fundamentals -v
"""

import copy

import pytest

from aisec_lab import load_lab_module

triage = load_lab_module(__file__, "triage")

INTEL = triage.load_intel()
CTX = triage.load_context()
ALERTS = triage.load_alerts()
RESULTS = {t.id: t for t in triage.triage_queue(ALERTS, INTEL, CTX)}


def run_one(alert, extra=()):
    """Triage one alert (optionally with extra queue context)."""
    res = triage.triage_queue([alert, *extra], INTEL, CTX)
    return next(t for t in res if t.id == alert["id"])


def alert(aid):
    return copy.deepcopy(next(a for a in ALERTS if a["id"] == aid))


# ---------- true positives ----------------------------------------------------------

@pytest.mark.parametrize("aid", ["A-1002", "A-1003", "A-1006", "A-1009", "A-1012", "A-1016"])
def test_real_attacks_are_true_positives(aid):
    assert RESULTS[aid].verdict == "true_positive"


def test_spray_then_success_declares_incident():
    assert RESULTS["A-1003"].escalation == "escalate_L3_declare_incident"
    assert "A-1002" in RESULTS["A-1003"].corroborating


def test_unapproved_domain_admin_add_on_dc_goes_to_l3():
    t = RESULTS["A-1009"]
    assert t.verdict == "true_positive"
    assert t.escalation == "escalate_L3_declare_incident"


def test_exfil_to_reputable_site_is_still_flagged():
    # The domain is "benign" in intel, but reputation is not intent.
    t = RESULTS["A-1014"]
    assert t.intel_hits[0]["verdict"] == "benign"
    assert t.verdict == "true_positive"


# ---------- tricky benign cases -------------------------------------------------------

@pytest.mark.parametrize("aid", ["A-1004", "A-1005", "A-1007", "A-1010", "A-1015"])
def test_benign_true_positives(aid):
    t = RESULTS[aid]
    assert t.verdict == "benign_true_positive"
    assert t.escalation == "close_benign_and_document"


@pytest.mark.parametrize("aid", ["A-1001", "A-1008", "A-1017"])
def test_false_positives(aid):
    assert RESULTS[aid].verdict == "false_positive"


def test_encoded_powershell_is_benign_only_inside_the_approved_change():
    a = alert("A-1005")
    assert run_one(a).verdict == "benign_true_positive"
    a["time"] = "2026-11-10T06:30:00Z"  # after the change window closed
    assert run_one(a).verdict != "benign_true_positive"


def test_change_window_needs_the_right_actor():
    a = alert("A-1005")
    a["user"] = "erin"  # a different person using the same host in the window
    assert run_one(a).verdict != "benign_true_positive"


def test_approved_change_cannot_excuse_a_malicious_domain():
    a = alert("A-1005")
    a["domain"] = "cdn-stage.example"
    t = run_one(a)
    assert t.verdict == "true_positive"
    assert "approved_change" not in t.benign_reasons


def test_approved_travel_cannot_excuse_a_tor_exit():
    a = alert("A-1015")
    a["src_ip"] = "203.0.113.99"
    assert run_one(a).verdict == "true_positive"


def test_wrong_change_ticket_is_not_accepted():
    a = alert("A-1010")
    a["details"]["change_ticket"] = "CHG-9999"
    assert run_one(a).verdict != "benign_true_positive"


def test_brute_force_with_success_is_not_dismissed_as_low_count():
    t = RESULTS["A-1013"]
    assert "below_threshold" not in t.benign_reasons
    assert t.verdict == "needs_investigation"


def test_scanner_rule_only_excuses_authorized_scanner_ips():
    a = alert("A-1004")
    a["src_ip"] = "192.0.2.99"  # not on the authorized list
    assert run_one(a).verdict != "benign_true_positive"


# ---------- mapping, scoring, notes ------------------------------------------------------

def test_every_rule_has_attack_mapping_with_valid_ids():
    import re
    for rule, meta in triage.RULES.items():
        assert meta["attack"], rule
        for tactic, tid, name in meta["attack"]:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), (rule, tid)
            assert tactic and name


def test_spray_maps_to_t1110_003():
    assert ("Credential Access", "T1110.003", "Password Spraying") in RESULTS["A-1002"].attack


def test_queue_is_sorted_by_score():
    scores = [t.score for t in triage.triage_queue(ALERTS, INTEL, CTX)]
    assert scores == sorted(scores, reverse=True)


def test_scores_stay_between_0_and_100():
    assert all(0 <= t.score <= 100 for t in RESULTS.values())


def test_case_notes_have_required_sections():
    for t in RESULTS.values():
        for part in ("What fired", "Enrichment", "Score:", "ATT&CK:", "Verdict:", "Recommended action", "Next steps"):
            assert part in t.notes, (t.id, part)


def test_notes_say_when_there_is_no_intel():
    assert "absence of intel is not proof of safety" in RESULTS["A-1005"].notes


def test_all_verdicts_are_known():
    assert {t.verdict for t in RESULTS.values()} <= set(triage.VERDICTS)
    assert len({t.verdict for t in RESULTS.values()}) == 4  # the queue exercises every verdict


def test_unknown_alert_alone_gets_no_corroboration():
    t = run_one(alert("A-1011"))  # alone in the queue
    assert t.corroborating == []
