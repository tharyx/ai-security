"""Tests for the Snyk-style container scan."""

import copy

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "snyk_lite")


def test_finds_issues_sorted_by_severity():
    issues = s.scan(s.IMAGE)
    assert [i["package"] for i in issues] == ["zlib1g", "openssl", "flask"]


def test_fixed_version_not_reported():
    img = copy.deepcopy(s.IMAGE)
    img["packages"][0]["version"] = "3.0.14"
    assert "openssl" not in {i["package"] for i in s.scan(img)}


def test_version_compare_is_numeric():
    img = {"packages": [{"name": "flask", "version": "3.0.10", "from": "app"}]}
    assert s.scan(img) == []  # 3.0.10 >= 3.0.4


def test_advice_differs_for_base_and_app_packages():
    adv = s.fix_advice(s.scan(s.IMAGE))
    assert any("openssl" in a and "base image" in a for a in adv)
    assert any("flask" in a and "lockfile" in a for a in adv)
    assert any("no fixed version" in a for a in adv)


def test_recommend_base_picks_fewest_issues():
    assert s.recommend_base("debian:12") == "distroless/static"
    assert s.recommend_base("distroless/static") is None


def test_gate_thresholds():
    issues = s.scan(s.IMAGE)
    assert not s.gate(issues, "high") and not s.gate(issues, "critical")
    medium_only = [i for i in issues if i["severity"] == "medium"]
    assert s.gate(medium_only, "high") and not s.gate(medium_only, "medium")


def test_clean_image_passes():
    assert s.gate(s.scan({"packages": [{"name": "bash", "version": "5.2", "from": "base"}]}))
