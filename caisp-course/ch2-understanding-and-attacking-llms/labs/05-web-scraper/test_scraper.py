from pathlib import Path

import pytest

from aisec_lab import MockLLM, load_lab_module

sc = load_lab_module(__file__, "scraper")
FIXTURE = Path(__file__).parent / "fixtures" / "product.html"


@pytest.fixture(scope="module")
def page():
    return sc.parse_file(str(FIXTURE))


def test_extracts_title_headings_links(page):
    assert page.title.startswith("QuietMouse 3000")
    assert page.headings == ["QuietMouse 3000", "Reviews"]
    assert page.links == ["/keyboard.html", "https://example.com/help"]


def test_script_and_style_text_are_not_content(page):
    everything = " ".join(page.visible_text + page.hidden_text)
    assert "tracking" not in everything and "display:none" not in everything


def test_hidden_text_and_comments_are_separated(page):
    hidden = " ".join(page.hidden_text)
    assert "HIJACKED-8842" in hidden and "system prompt" in hidden and "CALL_TOOL" in hidden
    assert any("note for AI" in c for c in page.comments)
    assert not any("HIJACKED" in t for t in page.visible_text)


def test_naive_pipeline_is_hijacked(page):
    out = sc.summarize(sc.naive_text(page), MockLLM())
    assert "send_email" in out and "attacker@evil.example" in out


def test_sanitized_pipeline_is_not_hijacked(page):
    clean, findings = sc.sanitize_for_llm(page)
    out = sc.summarize(clean, MockLLM())
    assert "HIJACKED" not in out and "CALL_TOOL" not in out
    assert "instructions" not in out.lower()
    assert any("hidden text dropped" in f for f in findings)
    assert any("injection phrase dropped" in f for f in findings)  # zero-width trick caught
    assert "QuietMouse" in out


def test_zero_width_chars_removed_before_matching(page):
    clean, _ = sc.sanitize_for_llm(page)
    assert "​" not in clean


def test_validate_url_blocks_dangerous_targets():
    for bad in ["file:///etc/passwd", "ftp://x.com/a", "http://localhost/admin",
                "http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data/",
                "http://10.0.0.5/"]:
        assert sc.validate_url(bad), bad
    assert sc.validate_url("https://example.com/page") is None


def test_robots_txt_is_respected():
    robots = "User-agent: *\nDisallow: /private/\n"
    assert sc.allowed_by_robots(robots, "https://example.com/public")
    assert not sc.allowed_by_robots(robots, "https://example.com/private/data")


def test_fetch_refuses_bad_url_without_network():
    with pytest.raises(ValueError):
        sc.fetch("http://127.0.0.1/")
