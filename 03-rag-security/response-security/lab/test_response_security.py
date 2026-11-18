"""Regression tests for the response-security lab. Tests check IMPACT on what the user's
chat window would render: attacker URLs (exfiltration channels), sensitive values on screen
or hidden inside a URL, and citations that lend false authority.

Run from the repository root:
    python -m pytest 03-rag-security/response-security -v
"""

import base64
import urllib.parse

import pytest

from aisec_lab import load_lab_module

attacks = load_lab_module(__file__, "attacks")
V = load_lab_module(__file__, "vulnerable_responder")
S = load_lab_module(__file__, "secure_responder")


def vulnerable():
    return V.VulnerableResponder(attacks.DOCS, attacks.ExfilProneLLM())


def secure(**flags):
    return S.SecureResponder(attacks.DOCS, attacks.ExfilProneLLM(), **flags)


def ask(app, name):
    return app.ask(attacks.ATTACKS[name])


# ---------- Part 1: prove the attacks are real ----------------------------------------

def test_zero_click_image_carries_customer_data_to_the_attacker():
    r = ask(vulnerable(), "markdown_image_exfil")
    image_urls = [u for u in attacks.attacker_urls(r.rendered) if "pixel.png?d=" in u]
    assert image_urls, "the rendered markdown should contain an attacker image URL"
    assert attacks.CUSTOMER_EMAIL in urllib.parse.unquote(image_urls[0])


def test_link_exfil_carries_customer_data_in_the_query_string():
    r = ask(vulnerable(), "link_exfil")
    assert any("verify.evil.example/login?d=" in u for u in attacks.attacker_urls(r.rendered))
    assert "national_id" in attacks.leaked_values(r.rendered)


def test_vulnerable_answer_shows_a_service_key():
    assert attacks.leaked_values(ask(vulnerable(), "secret_in_answer").rendered) == ["secret"]


def test_vulnerable_answer_shows_personal_data():
    leaked = attacks.leaked_values(ask(vulnerable(), "pii_in_answer").rendered)
    assert {"email", "phone", "national_id"} <= set(leaked)


def test_vulnerable_app_launders_a_false_claim_through_the_official_policy():
    assert attacks.laundered_citation(ask(vulnerable(), "citation_laundering"))


# ---------- Part 2: the response gate holds -------------------------------------------

@pytest.mark.parametrize("name", list(attacks.ATTACKS))
def test_no_attack_has_impact_on_the_secure_responder(name):
    r = ask(secure(), name)
    assert attacks.attacker_urls(r.rendered) == []
    assert attacks.leaked_values(r.rendered) == []
    assert not attacks.laundered_citation(r)


def test_secret_withholds_the_whole_answer_and_logs_only_the_type():
    app = secure()
    r = ask(app, "secret_in_answer")
    assert r.rendered == S.WITHHELD and r.citations == []
    assert {"kind": "secret_blocked", "types": ["LAB_SERVICE_KEY"]} in app.events
    assert attacks.SECRET_KEY not in repr(app.events)  # events hold types, never values


def test_personal_data_is_masked_but_the_answer_stays_useful():
    app = secure()
    r = ask(app, "pii_in_answer")
    assert "[EMAIL]" in r.rendered and "[PHONE]" in r.rendered and "Account status is active" in r.rendered
    assert attacks.CUSTOMER_EMAIL not in repr(app.events)


def test_unsupported_citation_is_removed_and_the_user_is_told():
    app = secure()
    r = ask(app, "citation_laundering")
    assert "[doc:refund-policy]" not in r.rendered and "refund-policy" not in r.citations
    assert "citation was removed" in r.rendered
    assert any(e["kind"] == "citation_removed" and e["reason"] == "not supported" for e in app.events)


def test_citation_to_a_document_that_was_not_retrieved_is_removed():
    gate = secure()
    text, kept = gate.check_citations("Deploys need two reviewers [doc:deploy-runbook]", {"refund-policy"})
    assert kept == [] and "[doc:deploy-runbook]" not in text
    assert gate.events[-1]["reason"] == "not retrieved"


@pytest.mark.parametrize("name", list(attacks.BENIGN))
def test_benign_answer_keeps_its_allowlisted_link_and_valid_citation(name):
    question, expected = attacks.BENIGN[name]
    app = secure()
    r = app.ask(question)
    assert expected in r.rendered and r.citations == ["refund-policy"]
    assert app.events == []


# ---------- Part 3: which layer holds on its own? -------------------------------------

@pytest.mark.parametrize("name", ["markdown_image_exfil", "link_exfil"])
def test_url_policy_alone_closes_the_exfil_channel(name):
    r = ask(secure(dlp=False, validate_citations=False), name)
    assert attacks.attacker_urls(r.rendered) == []


@pytest.mark.parametrize("name", ["markdown_image_exfil", "link_exfil"])
def test_dlp_alone_catches_personal_data_hidden_inside_a_url(name):
    """DLP also scans the URL-decoded text, so PII smuggled in a query string is caught."""
    app = secure(url_policy=False, validate_citations=False)
    r = ask(app, name)
    assert attacks.leaked_values(r.rendered) == []
    assert any(e["kind"] == "pii_blocked" for e in app.events)


def test_without_url_policy_data_that_dlp_cannot_recognize_still_leaves():
    """Limit: DLP only knows patterns. Business data (a discount floor) has no pattern,
    so only the URL policy stops it from leaving through the image."""
    docs = [{"doc_id": "pricing", "trust": "confidential", "title": "Pricing",
             "text": "Customer status pricing: the discount floor is 40 percent."},
            next(d for d in attacks.DOCS if d["doc_id"] == "status-wiki")]
    question = "What is the customer status pricing?"
    leaky = S.SecureResponder(docs, attacks.ExfilProneLLM(), url_policy=False).ask(question)
    assert any("discount%20floor" in u for u in attacks.attacker_urls(leaky.rendered))
    safe = S.SecureResponder(docs, attacks.ExfilProneLLM()).ask(question)
    assert attacks.attacker_urls(safe.rendered) == []


def test_dlp_misses_an_encoded_secret():
    """Limit: a base64-encoded (or translated) secret has no known pattern. The real fix is
    upstream: secrets never go into the index (see document-security, PII and secrets)."""
    encoded = base64.b64encode(attacks.SECRET_KEY.encode()).decode()
    assert S.SecureResponder.dlp_findings(f"Here it is: {encoded}") == ([], [])


def test_without_citation_validation_the_fake_citation_survives():
    assert attacks.laundered_citation(ask(secure(validate_citations=False), "citation_laundering"))
