import json
import pathlib

import pytest

from aisec_lab import load_lab_module

dm = load_lab_module(__file__, "dojo_model")
FX = pathlib.Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FX / name).read_text())


@pytest.fixture
def world():
    d = dm.Dojo(dedupe_scope="product")
    p = d.add_product("app")
    e = d.add_engagement(p, "rel")
    return d, p, e


def test_hierarchy(world):
    d, p, e = world
    t = d.add_test(e, "SARIF")
    assert p.engagements[0] is e and e.tests[0] is t and t.engagement_id == e.id


def test_sarif_parsing_severity_and_cwe():
    fs = {f.unique_id_from_tool: f for f in dm.parse_sarif(load("sast.sarif.json"))}
    assert fs["FX-SQLI-1"].severity == "High" and fs["FX-SQLI-1"].cwe == 89
    assert fs["FX-SQLI-1"].file_path == "app/db.py" and fs["FX-SQLI-1"].line == 42
    assert fs["FX-HASH-2"].severity == "Medium"
    assert fs["FX-LOG-3"].severity == "Low"  # falls back to the SARIF level (note)


def test_trivy_parsing():
    fs = dm.parse_trivy(load("trivy-fs.json"))
    assert len(fs) == 3
    crit = next(f for f in fs if f.component_name == "minimist")
    assert crit.severity == "Critical" and crit.cve == "CVE-2021-44906" and crit.fix_available == "1.2.6"


def test_import_creates_findings(world):
    d, p, e = world
    t = d.add_test(e, "SARIF")
    assert d.import_scan(t, "SARIF", load("sast.sarif.json")) == {"created": 3, "duplicates": 0}
    assert len(t.findings) == 3


def test_same_cve_in_two_files_is_deduplicated(world):
    d, p, e = world
    t = d.add_test(e, "Trivy Scan")
    res = d.import_scan(t, "Trivy Scan", load("trivy-fs.json"))
    # lodash appears in package-lock.json and requirements.txt, but the hash ignores the file.
    assert res == {"created": 2, "duplicates": 1}
    dup = next(f for f in t.findings if f.duplicate)
    assert not dup.active and dup.duplicate_of is not None


def test_second_import_is_all_duplicates(world):
    d, p, e = world
    t = d.add_test(e, "Trivy Scan")
    d.import_scan(t, "Trivy Scan", load("trivy-fs.json"))
    res = d.import_scan(t, "Trivy Scan", load("trivy-fs.json"))
    assert res["created"] == 0 and res["duplicates"] == 3


def test_duplicates_not_counted_as_open(world):
    d, p, e = world
    t = d.add_test(e, "Trivy Scan")
    d.import_scan(t, "Trivy Scan", load("trivy-fs.json"))
    d.import_scan(t, "Trivy Scan", load("trivy-fs.json"))
    assert d.counts_by_severity(p) == {"Critical": 1, "High": 1, "Medium": 0, "Low": 0, "Info": 0}


def test_dedupe_scope_product_crosses_engagements(world):
    d, p, e = world
    d.import_scan(d.add_test(e, "Trivy Scan"), "Trivy Scan", load("trivy-fs.json"))
    t2 = d.add_test(d.add_engagement(p, "nightly"), "Trivy Scan")
    assert d.import_scan(t2, "Trivy Scan", load("trivy-fs.json"))["created"] == 0


def test_dedupe_scope_engagement_does_not_cross():
    d = dm.Dojo(dedupe_scope="engagement")
    p = d.add_product("app")
    d.import_scan(d.add_test(d.add_engagement(p, "a"), "Trivy Scan"), "Trivy Scan", load("trivy-fs.json"))
    t2 = d.add_test(d.add_engagement(p, "b"), "Trivy Scan")
    assert d.import_scan(t2, "Trivy Scan", load("trivy-fs.json"))["created"] == 2


def test_different_scanner_same_issue_is_not_merged_by_hash(world):
    # SAST and SCA describe different things; their hash fields differ, so no false merge.
    d, p, e = world
    d.import_scan(d.add_test(e, "SARIF"), "SARIF", load("sast.sarif.json"))
    res = d.import_scan(d.add_test(e, "Trivy Scan"), "Trivy Scan", load("trivy-fs.json"))
    assert res["created"] == 2


def test_reimport_closes_fixed_findings(world):
    d, p, e = world
    t = d.add_test(e, "Trivy Scan")
    d.import_scan(t, "Trivy Scan", load("trivy-fs.json"))
    res = d.reimport_scan(t, "Trivy Scan", load("trivy-fs-rescan.json"))
    assert res["closed"] == 1 and res["created"] == 0
    lodash = next(f for f in t.findings if f.component_name == "lodash" and not f.duplicate)
    assert lodash.is_mitigated and not lodash.active


def test_reimport_reopens_regression(world):
    d, p, e = world
    t = d.add_test(e, "Trivy Scan")
    d.import_scan(t, "Trivy Scan", load("trivy-fs.json"))
    d.reimport_scan(t, "Trivy Scan", load("trivy-fs-rescan.json"))
    res = d.reimport_scan(t, "Trivy Scan", load("trivy-fs.json"))
    assert res["reopened"] == 1


def test_false_positive_and_risk_accepted_leave_open_counts(world):
    d, p, e = world
    t = d.add_test(e, "SARIF")
    d.import_scan(t, "SARIF", load("sast.sarif.json"))
    before = sum(d.counts_by_severity(p).values())
    t.findings[0].false_p = True
    t.findings[1].risk_accepted = True
    assert sum(d.counts_by_severity(p).values()) == before - 2


@pytest.mark.parametrize("raw,expected", [("HIGH", "High"), ("moderate", "Medium"), ("weird", "Info"), ("", "Info")])
def test_normalise_severity(raw, expected):
    assert dm.normalise_severity(raw) == expected


def test_invalid_dedupe_scope():
    with pytest.raises(AssertionError):
        dm.Dojo(dedupe_scope="galaxy")
