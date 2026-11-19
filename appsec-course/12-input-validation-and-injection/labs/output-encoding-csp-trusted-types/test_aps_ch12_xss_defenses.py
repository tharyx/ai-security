import pytest

from aisec_lab import load_lab_module

x = load_lab_module(__file__, "xss_defenses")
PAYLOADS = {"html": "<img src=x onerror=alert(1)>", "attribute": '" autofocus onfocus="alert(1)',
            "javascript": "';alert(1);//", "css": "red; background:url(//evil.example/x)"}


@pytest.mark.parametrize("ctx", list(PAYLOADS))
def test_raw_output_breaks_out_and_context_encoding_contains_it(ctx):
    assert x.breaks_out(ctx, x.render(ctx, PAYLOADS[ctx], encode=False))
    assert not x.breaks_out(ctx, x.render(ctx, PAYLOADS[ctx], encode=True))


def test_html_encoding_is_the_wrong_encoder_inside_an_event_handler():
    payload = "');alert(1);//"
    assert x.onclick_handler_breaks_out(payload, x.html_encode)  # decoded before JS runs
    assert not x.onclick_handler_breaks_out(payload, x.js_string_encode)
    assert x.js_string_encode("</script>") == r"\x3c\x2fscript\x3e"


def test_csp_evaluator_flags_weak_policy_and_passes_strict_one():
    weak = "default-src 'self'; script-src 'self' 'unsafe-inline' https://ajax.googleapis.com"
    findings = x.evaluate_csp(weak)
    assert any("unsafe-inline" in f for f in findings) and any("base-uri" in f for f in findings)
    assert x.evaluate_csp(x.build_strict_csp(x.new_nonce())) == []


def test_strict_csp_blocks_injected_inline_script_but_allows_nonced_one():
    n = x.new_nonce()
    csp = x.build_strict_csp(n)
    assert x.browser_runs_inline_script(None, "<script>evil()</script>")
    assert not x.browser_runs_inline_script(csp, "<script>evil()</script>")
    assert not x.browser_runs_inline_script(csp, '<script nonce="guess">evil()</script>')
    assert x.browser_runs_inline_script(csp, f'<script nonce="{n}">app()</script>')


def test_unsafe_inline_is_ignored_when_a_nonce_is_present():
    csp = "script-src 'nonce-abc' 'unsafe-inline'"
    assert not x.browser_runs_inline_script(csp, "<script>evil()</script>")


def test_trusted_types_block_plain_string_and_policy_sanitizes():
    evil = 'Hi <img src=x onerror="alert(1)"><script>a()</script>'
    plain = x.FakeElement(False)
    plain.innerHTML = evil
    assert x.element_has_script(plain)
    tt = x.FakeElement(True)
    with pytest.raises(TypeError):
        tt.innerHTML = evil
    tt.innerHTML = x.TrustedTypePolicy("s", x.simple_sanitizer).createHTML(evil)
    assert not x.element_has_script(tt) and tt.innerHTML.startswith("Hi")


def test_default_policy_handles_legacy_string_assignments():
    el = x.FakeElement(True, default_policy=x.TrustedTypePolicy("default", x.simple_sanitizer))
    el.innerHTML = "<b>ok</b><svg onload=alert(1)>"
    assert el.innerHTML == "<b>ok</b>"
