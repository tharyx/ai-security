"""Tests for the bomber-style SBOM scanner."""

from aisec_lab import load_lab_module

b = load_lab_module(__file__, "bomber_lite")


def test_matches_vulnerable_components_only():
    res = b.scan(b.SBOM)
    assert {v["id"] for v in res["vulnerabilities"]} == {"EXAMPLE-OSV-0001", "EXAMPLE-OSV-0002"}


def test_version_outside_range_not_matched():
    # left-padz 2.1.0 is >= fixed 2.0.0 ; flask has no advisory
    pk = {v["package"] for v in b.scan(b.SBOM)["vulnerabilities"]}
    assert "left-padz@2.1.0" not in pk and "flask@3.0.3" not in pk


def test_component_without_purl_is_reported_unmatched():
    assert b.scan(b.SBOM)["unmatched_components"] == ["mystery"]


def test_sorted_by_severity():
    assert [v["severity"] for v in b.scan(b.SBOM)["vulnerabilities"]] == ["CRITICAL", "HIGH"]


def test_fixed_version_reported():
    assert {v["fixed"] for v in b.scan(b.SBOM)["vulnerabilities"]} == {"1.2.5", "4.19.2"}


def test_in_range_boundaries():
    ev = [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]
    assert b.in_range("1.0.0", ev) and b.in_range("1.9.9", ev)
    assert not b.in_range("2.0.0", ev) and not b.in_range("0.9.0", ev)
    assert b.in_range("1.10.0", [{"introduced": "0"}, {"fixed": "1.12.0"}])


def test_parse_purl_variants():
    assert b.parse_purl("pkg:pypi/flask@3.0.3") == ("PyPI", "flask", "3.0.3")
    assert b.parse_purl("pkg:npm/express@4.17.1") == ("npm", "express", "4.17.1")
    assert b.parse_purl("pkg:deb/debian/openssl@3.0?arch=amd64") == ("deb", "openssl", "3.0?arch=amd64")
    assert b.parse_purl("garbage") is None


def test_ignore_by_id_or_alias():
    assert len(b.scan(b.SBOM, ignore_ids={"EXAMPLE-OSV-0002"})["vulnerabilities"]) == 1
    assert len(b.scan(b.SBOM, ignore_ids={"CVE-2099-0001"})["vulnerabilities"]) == 1


def test_exit_code_threshold_and_summary():
    res = b.scan(b.SBOM)
    assert b.exit_code(res) == 1 and b.summary(res) == {"total": 2, "unmatched": 1, "CRITICAL": 1, "HIGH": 1}
    assert b.exit_code(b.scan(b.SBOM, ignore_ids={"EXAMPLE-OSV-0002"}), "CRITICAL") == 0
