from pathlib import Path

import pytest
from aisec_lab import load_lab_module

cp = load_lab_module(__file__, "composer")
TEXT = (Path(__file__).parent / "fixtures" / "compose.yml").read_text()
DOC = cp.load(TEXT)


def test_depends_list_and_map_forms():
    g = cp.graph(DOC)
    assert g["web"] == ["api"] and g["api"] == ["cache", "db"]


def test_start_order_dependencies_first():
    order = cp.start_order(DOC)
    assert order.index("db") < order.index("api") < order.index("web")
    assert order.index("cache") < order.index("api")


def test_cycle_detected():
    doc = cp.load("services:\n  a: {image: x, depends_on: [b]}\n  b: {image: x, depends_on: [a]}\n")
    with pytest.raises(cp.ComposeError, match="cycle"):
        cp.start_order(doc)


def test_unknown_dependency():
    doc = cp.load("services:\n  a: {image: x, depends_on: [ghost]}\n")
    with pytest.raises(cp.ComposeError, match="unknown"):
        cp.graph(doc)


def test_review_flags_the_dangerous_ones():
    msgs = [(s, n, m) for s, n, m in cp.review(DOC)]
    crit = {(n) for s, n, _ in msgs if s == "CRITICAL"}
    assert crit == {"cache"}
    text = " ".join(m for _, _, m in msgs)
    assert "docker.sock" in text and "network_mode: host" in text and "SYS_ADMIN" in text


def test_review_flags_secret_and_wide_port_and_latest():
    got = {(n, m.split(" ")[0]) for _, n, m in cp.review(DOC)}
    assert ("api", "secret") in got
    assert any(n == "web" and "port 80:80" in m for _, n, m in cp.review(DOC))
    assert any(n == "web" and "not pinned" in m for _, n, m in cp.review(DOC))


def test_loopback_port_not_flagged_and_pinned_db_clean():
    r = cp.review(DOC)
    assert not any(n == "api" and "port" in m for _, n, m in r)
    assert not any(n == "db" and s != "LOW" for s, n, _ in r)


def test_healthy_condition_needs_healthcheck():
    doc = cp.load("services:\n  a: {image: 'x:1', depends_on: {b: {condition: service_healthy}}}\n  b: {image: 'y:1'}\n")
    assert any("never start" in m for _, _, m in cp.review(doc))


def test_missing_services_key():
    with pytest.raises(cp.ComposeError):
        cp.load("version: '3'\n")
