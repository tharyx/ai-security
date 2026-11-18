"""Right-to-erasure and incident-clock tests. Assert impact: can the assistant still
reveal the person's data? Which regulator must hear first?

Run from the repository root:
    python -m pytest 08-ai-compliance -v
"""

from datetime import date, datetime, timedelta

from aisec_lab import load_lab_module

pr = load_lab_module(__file__, "privacy_rights")
clock = load_lab_module(__file__, "incident_clock")
vuln = load_lab_module(__file__, "vulnerable_compliance")

TODAY = date(2026, 11, 15)
Q = "What is the email for loyalty id L-5521?"
EMAIL = "asha.verma@customer.example"
IDS = [EMAIL, "Asha Verma", "L-5521"]


# ---------- erasure ----------------------------------------------------------------------

def test_naive_erasure_leaves_the_person_answerable():
    s = pr.demo_store(TODAY)
    vuln.naive_erasure(s, "cust-5521")
    assert EMAIL in s.ask(Q)  # source gone, but cache and index still serve it


def test_layered_erasure_removes_every_live_copy():
    s = pr.demo_store(TODAY)
    receipt = s.erase_subject("cust-5521", IDS, TODAY)
    assert EMAIL not in s.ask(Q)
    assert all(EMAIL not in str(entry) for entry in s.logs[:-1])  # history redacted
    assert receipt.removed["index_chunks"] == 2


def test_cache_alone_still_leaks_if_not_purged():
    s = pr.demo_store(TODAY)
    s.erase_subject("cust-5521", IDS, TODAY, purge_cache=False)
    assert EMAIL in s.ask(Q)


def test_index_alone_still_leaks_if_not_propagated():
    s = pr.demo_store(TODAY)
    s.erase_subject("cust-5521", IDS, TODAY, propagate_index=False)
    assert EMAIL in s.ask(Q)


def test_logs_are_redacted_not_deleted():
    s = pr.demo_store(TODAY)
    before = len(s.logs)
    s.erase_subject("cust-5521", IDS, TODAY)
    assert len(s.logs) == before            # the event record survives (audit / AI Act logs)
    assert EMAIL not in str(s.logs)         # the personal data does not


def test_other_customers_are_unaffected():
    s = pr.demo_store(TODAY)
    s.erase_subject("cust-5521", IDS, TODAY)
    assert "L-7310" in s.ask("Which loyalty id did Ravi Iyer give?")


def test_receipt_is_honest_about_backups_and_fine_tuned_models():
    s = pr.demo_store(TODAY)
    s.use_for_fine_tuning("FT-2026-07")
    r = s.erase_subject("cust-5521", IDS, TODAY)
    assert not r.complete
    assert any("backup" in p for p in r.pending)
    assert any("cannot erase from weights" in p for p in r.pending)


def test_backup_past_retention_is_not_pending():
    s = pr.demo_store(TODAY)
    r = s.erase_subject("cust-5521", IDS, TODAY + timedelta(days=60))
    assert not any("backup" in p for p in r.pending)


# ---------- incident clocks --------------------------------------------------------------

AWARE = datetime(2026, 11, 14, 9, 0)


def test_shortest_clock_comes_first():
    clocks = clock.reporting_clocks({"aware_at": AWARE, "eu_high_risk_provider": True,
                                     "eu_serious_incident": True, "personal_data_breach": True,
                                     "eu_personal_data": True, "india_reportable_cyber_incident": True})
    assert [c.regime for c in clocks] == ["CERT-In", "GDPR", "EU AI Act"]
    assert clocks[0].deadline == AWARE + timedelta(hours=6)


def test_ai_act_clock_shortens_for_death_and_critical_infrastructure():
    base = {"aware_at": AWARE, "eu_high_risk_provider": True, "eu_serious_incident": True}
    days = lambda **kw: (clock.reporting_clocks({**base, **kw})[0].deadline - AWARE).days  # noqa: E731
    assert (days(), days(death=True), days(widespread_or_critical_infrastructure=True)) == (15, 10, 2)


def test_breach_unlikely_to_risk_people_does_not_start_the_gdpr_clock():
    clocks = clock.reporting_clocks({"aware_at": AWARE, "personal_data_breach": True,
                                     "eu_personal_data": True, "risk_to_individuals": False})
    assert clocks == []


def test_no_incident_flags_means_no_clocks():
    assert clock.reporting_clocks({"aware_at": AWARE}) == []


def test_dpdp_rules_clock_is_phased():
    # DPDP Rules 2025 were notified in Nov 2025; breach-reporting duties commence ~18 months later.
    before = clock.reporting_clocks({"aware_at": AWARE, "personal_data_breach": True,
                                     "india_personal_data": True})
    assert [c.regime for c in before] == ["DPDP Act"] and "not yet commenced" in before[0].basis
    later = datetime(2027, 6, 1, 9, 0)
    after = clock.reporting_clocks({"aware_at": later, "personal_data_breach": True,
                                    "india_personal_data": True})
    rules = next(c for c in after if c.regime == "DPDP Rules")
    assert rules.deadline == later + timedelta(hours=72)


def test_ai_act_clock_is_practice_only_before_the_omnibus_high_risk_date():
    base = {"eu_high_risk_provider": True, "eu_serious_incident": True}
    before = clock.reporting_clocks({**base, "aware_at": AWARE})[0]
    assert "practice only" in before.basis and "2027-12-02" in before.basis
    after = clock.reporting_clocks({**base, "aware_at": datetime(2028, 1, 10, 9, 0)})[0]
    assert "practice only" not in after.basis
    product = clock.reporting_clocks({**base, "aware_at": datetime(2028, 1, 10, 9, 0), "annex_i_product": True})[0]
    assert "2028-08-02" in product.basis
