import pytest

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "render")


def test_clean_profile_has_no_findings_in_either_version():
    assert r.xss_findings(r.page_vuln(r.SAFE_USER)) == []
    assert r.xss_findings(r.page_secure(r.SAFE_USER)) == []


@pytest.mark.parametrize("field", list(r.PAYLOADS))
def test_payload_executes_in_vulnerable_page(field):
    assert r.xss_findings(r.page_vuln(r.with_payload(field))), field


@pytest.mark.parametrize("field", list(r.PAYLOADS))
def test_context_encoding_neutralizes_payload(field):
    assert r.xss_findings(r.page_secure(r.with_payload(field))) == [], field


def test_script_close_tag_breakout_is_blocked_by_js_encoding():
    u = dict(r.SAFE_USER, nickname="</script><script>alert(1)</script>")
    assert any("extra <script>" in f for f in r.xss_findings(r.page_vuln(u)))
    page = r.page_secure(u)
    assert "\\u003c/script\\u003e" in page and r.xss_findings(page) == []


def test_html_escape_alone_is_not_enough_for_an_unquoted_attribute():
    escaped_but_unquoted = f"<div title={r.enc_html(r.PAYLOADS['bio'])}>bio</div>"
    assert any("onmouseover" in f for f in r.xss_findings(escaped_but_unquoted))


def test_url_encoding_blocks_scheme_tricks_but_keeps_real_links():
    for bad in ("javascript:alert(1)", " JaVaScRiPt:alert(1)", "data:text/html,<b>x</b>"):
        assert r.enc_url(bad) == "#"
    assert r.enc_url("https://asha.example/a?x=1&y=2") == "https://asha.example/a?x=1&amp;y=2"


def test_css_value_is_validated_not_encoded():
    assert r.enc_css_color("#336699") == "#336699"
    assert r.enc_css_color("red;background:url(javascript:alert(1))") == "#000000"


def test_legitimate_text_survives_encoding():
    u = dict(r.SAFE_USER, name="Tom & Jerry <3")
    assert "<h2>Tom &amp; Jerry &lt;3</h2>" in r.page_secure(u)
