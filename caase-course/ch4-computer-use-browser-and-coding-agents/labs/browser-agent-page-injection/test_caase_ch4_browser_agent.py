"""Tests: a mock DOM-parsing browser agent versus hidden-text, off-screen, alt-text and overlay pages."""

from pathlib import Path

import pytest

from aisec_lab import load_lab_module

b = load_lab_module(__file__, "browser_agent")
FIX = Path(__file__).resolve().parent / "fixtures"


def page(name):
    return (FIX / name).read_text()


SINK = "collector.attacker.example"


def test_benign_page_triggers_nothing_even_for_a_naive_agent():
    w = b.run(page("benign.html"), b.Defenses())
    assert (w.navigations, w.clicks, w.credentials_sent, w.grants) == ([], [], [], [])


def test_hidden_text_hijacks_a_naive_agent():
    w = b.run(page("hidden-text.html"), b.Defenses())
    assert any(SINK in u for u in w.navigations)
    assert w.credentials_sent == [b.FAKE_PASSWORD]
    assert "Export" in w.clicks


def test_offscreen_div_hijacks_a_naive_agent():
    assert any(SINK in u for u in b.run(page("offscreen.html"), b.Defenses()).navigations)


def test_alt_title_and_aria_label_hijack_a_naive_agent():
    w = b.run(page("alt-text.html"), b.Defenses())
    assert any(SINK in u for u in w.navigations)
    assert "Export" in w.clicks and w.credentials_sent


def test_fake_allow_overlay_tricks_a_naive_agent_into_granting():
    w = b.run(page("fake-allow-overlay.html"), b.Defenses())
    assert w.grants == ["permissions"] and "Allow" in w.clicks


@pytest.mark.parametrize("name", ["hidden-text.html", "offscreen.html", "alt-text.html", "fake-allow-overlay.html"])
def test_visible_text_only_perception_stops_every_fixture(name):
    w = b.run(page(name), b.Defenses(visible_only=True))
    assert (w.navigations, w.clicks, w.credentials_sent, w.grants) == ([], [], [], [])


def test_visible_mode_keeps_real_content_and_reports_flags():
    p = b.perceive(page("hidden-text.html"), "visible")
    assert "Laptop review" in p.text and "The laptop is fast and the battery lasts all day." in p.text
    assert not any("AGENT" in t for t in p.text)
    assert any(f.startswith("hidden") for f in p.flags)
    assert any(f == "overlay element" for f in b.perceive(page("fake-allow-overlay.html"), "visible").flags)


def test_domain_allowlist_alone_stops_navigation_exfil_only():
    d = b.Defenses(domain_allowlist=("blog.example",))
    w = b.run(page("hidden-text.html"), d)
    assert w.navigations == []
    assert w.credentials_sent == [b.FAKE_PASSWORD]      # other layers needed


def test_allowlist_matches_subdomains_but_not_lookalikes():
    assert b._host_ok("https://www.blog.example/x", ("blog.example",))
    assert not b._host_ok("https://blog.example.attacker.example/x", ("blog.example",))
    assert not b._host_ok("https://notblog.example/", ("blog.example",))


def test_no_autofill_alone_stops_credential_fill():
    w = b.run(page("hidden-text.html"), b.Defenses(no_autofill=True))
    assert w.credentials_sent == []


def test_approval_list_gates_grant_and_download_clicks():
    d = b.Defenses(approval_actions=("grant-permissions", "download"))
    w = b.run(page("fake-allow-overlay.html"), d)
    assert w.grants == [] and w.clicks == []
    ok = b.Defenses(approval_actions=("grant-permissions",), approve=lambda a: True)
    assert b.run(page("fake-allow-overlay.html"), ok).grants == ["permissions"]


def test_all_defences_together():
    d = b.Defenses(visible_only=True, domain_allowlist=("blog.example",), no_autofill=True,
                   approval_actions=("grant-permissions", "download", "export"))
    for name in ("hidden-text.html", "offscreen.html", "alt-text.html", "fake-allow-overlay.html"):
        w = b.run(page(name), d)
        assert (w.navigations, w.credentials_sent, w.grants) == ([], [], [])


def test_is_hidden_rules():
    assert b.is_hidden({"style": "display:none"})
    assert b.is_hidden({"style": "left:-9999px"})
    assert b.is_hidden({"aria-hidden": "true"})
    assert b.is_hidden({"style": "color:white"})
    assert not b.is_hidden({"style": "color:#111"})
