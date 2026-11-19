"""Tests for the Equifax-style exposure finder."""

from datetime import date
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

x = load_lab_module(__file__, "exposure")
FIX = Path(__file__).parent / "fixtures"
ASSETS, ADVS = x.load(FIX)
BREACH = date(2017, 5, 13)


def finding(fs, asset):
    return next(f for f in fs if f.asset == asset)


@pytest.mark.parametrize("version,hit", [
    ("2.3.5", True), ("2.3.31", True), ("2.3.32", False), ("2.3.4", False),
    ("2.5", True), ("2.5.10", True), ("2.5.10.1", False), ("2.5.12", False), ("2.4.0", False),
])
def test_version_range_boundaries(version, hit):
    assert x.version_affected(version, ADVS[0]["affected"]) is hit


def test_unparseable_version_raises():
    with pytest.raises(ValueError):
        x.parse_version("2.3.x")


def test_finds_the_vulnerable_component_and_only_it():
    fs, _ = x.find_vulnerabilities(ASSETS, ADVS, BREACH)
    assert [f.asset for f in fs] == ["dispute-portal"]
    f = fs[0]
    assert f.advisory == "CVE-2017-5638" and f.component == "struts2-core" and f.version == "2.3.31"
    assert "2.3.32" in f.fixed_in


def test_non_matching_low_advisory_is_not_flagged():
    fs, _ = x.find_vulnerabilities(ASSETS, ADVS, BREACH)
    assert all(f.advisory != "CVE-0000-0001" for f in fs)


def test_days_exposed_at_breach_date():
    f = finding(x.find_vulnerabilities(ASSETS, ADVS, BREACH)[0], "dispute-portal")
    assert f.days_exposed == (BREACH - date(2017, 3, 7)).days == 67


def test_sla_breach_for_critical():
    f = finding(x.find_vulnerabilities(ASSETS, ADVS, BREACH)[0], "dispute-portal")
    assert f.sla_days == 2 and f.sla_breached


def test_within_sla_if_checked_early():
    f = finding(x.find_vulnerabilities(ASSETS, ADVS, date(2017, 3, 8))[0], "dispute-portal")
    assert f.days_exposed == 1 and not f.sla_breached


def test_patching_stops_the_clock():
    fs, _ = x.find_vulnerabilities(ASSETS, ADVS, date(2017, 12, 1), patched_on={"dispute-portal": "2017-03-08"})
    assert fs[0].days_exposed == 1 and not fs[0].sla_breached


def test_custom_sla_changes_the_verdict():
    fs, _ = x.find_vulnerabilities(ASSETS, ADVS, BREACH, sla={**x.DEFAULT_SLA, "critical": 90})
    assert not fs[0].sla_breached


def test_inventory_gaps_are_reported():
    _, gaps = x.find_vulnerabilities(ASSETS, ADVS, BREACH)
    problems = {(g.asset, g.problem.split(":")[0]) for g in gaps}
    assert ("legacy-intake", "no components recorded") in problems
    assert ("legacy-intake", "no owner") in problems


def test_unparseable_inventory_version_becomes_a_gap():
    assets = [{"id": "a", "host": "a.example", "owner": "t", "internet_facing": True, "criticality": "low",
               "components": [{"name": "struts2-core", "version": "2.3.x", "kind": "java-lib"}]}]
    fs, gaps = x.find_vulnerabilities(assets, ADVS, BREACH)
    assert fs == [] and "cannot parse" in gaps[0].problem


def test_internet_facing_sorted_first():
    assets = ASSETS + [{"id": "internal-old", "host": "old.internal.example", "owner": "t",
                        "internet_facing": False, "criticality": "low",
                        "components": [{"name": "struts2-core", "version": "2.3.20", "kind": "java-lib"}]}]
    fs, _ = x.find_vulnerabilities(assets, ADVS, BREACH)
    assert [f.asset for f in fs] == ["dispute-portal", "internal-old"]


def test_timeline_gaps():
    tl = x.timeline(ADVS[0], "2017-03-15", "2017-05-13", "2017-07-29", "2017-08-01")
    gaps = {k: d for k, _, d in tl}
    assert gaps["advisory_published"] == 0
    assert gaps["exploited_in_wild"] == 3
    assert gaps["intrusion_began"] == 67
    assert gaps["breach_discovered"] > gaps["intrusion_began"]


def test_fixtures_are_synthetic():
    text = (FIX / "inventory.json").read_text()
    assert ".example" in text and "equifax" not in text.lower().replace("not equifax data", "")
