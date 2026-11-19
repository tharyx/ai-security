import json
from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "mvnscan")
osv = m.osv
HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"
DB = osv.load_db(HERE.parent / "_shared" / "advisories.osv.json")
DEPS, WARNS = m.parse_pom(FIX / "pom.xml")
BY = {d.artifact: d for d in DEPS}


def test_properties_and_dependency_management_are_resolved():
    assert BY["widgetlib-core"].version == "2.4.1"
    assert BY["jsonmark"].version == "1.2.0"
    assert BY["acme-web"].version == "3.1.0"          # no <version>, taken from dependencyManagement
    assert BY["widgetlib-test-utils"].scope == "test"


def test_unresolved_property_is_reported_not_guessed():
    assert BY["mystery-lib"].version is None
    assert any("mystery.version" in w for w in WARNS)


def test_cpe_candidates_strip_artifact_suffixes_and_noise_vendors():
    c = m.cpe_candidates(BY["widgetlib-test-utils"])
    assert ("example", "widgetlib", False) in c and ("example", "widgetlib-test-utils", True) in c
    assert all(v not in ("com", "org") for v, _, _ in c)


def test_cpe_mode_finds_real_and_false_positive_matches():
    ids = {(f.package, f.advisory) for f in m.scan(DEPS, DB, "cpe")}
    assert ("com.example.widget:widgetlib-core", "DSO-OSV-0201") in ids
    assert ("org.sample:jsonmark", "DSO-OSV-0202") in ids
    assert ("com.example.widget:widgetlib-docs", "DSO-OSV-0201") in ids       # false positive by name


def test_confidence_levels():
    f = {x.package: x for x in m.scan(DEPS, DB, "cpe")}
    assert m.confidence_of(f["org.sample:jsonmark"]) == "HIGHEST"
    assert m.confidence_of(f["com.example.widget:widgetlib-core"]) == "MEDIUM"


def test_test_scope_is_skipped_by_default_and_included_on_request():
    assert not any("test-utils" in f.package for f in m.scan(DEPS, DB, "cpe"))
    assert any("test-utils" in f.package for f in m.scan(DEPS, DB, "cpe", skip_test_scope=False))


def test_coordinate_mode_has_no_name_collision_false_positives():
    pk = {f.package for f in m.scan(DEPS, DB, "coordinate", skip_test_scope=False)}
    assert pk == {"com.example.widget:widgetlib-core", "org.sample:jsonmark"}


def test_fixed_version_is_clean():
    assert not any("acme-web" in f.package for f in m.scan(DEPS, DB, "cpe"))      # 3.1.0 is the fix


def test_suppression_removes_the_false_positive():
    sup = json.loads((FIX / "suppressions.json").read_text())
    kept, supp, _ = osv.apply_ignores(m.scan(DEPS, DB, "cpe"), sup, date(2026, 11, 19))
    assert [f.package for f in supp] == ["com.example.widget:widgetlib-docs"]
    assert len(kept) == 2


def test_break_build_by_cvss_and_confidence():
    f = m.scan(DEPS, DB, "cpe")
    assert m.break_build(f, 7.0) == 1
    assert m.break_build(f, 9.0) == 0
    only_medium = [x for x in f if m.confidence_of(x) == "MEDIUM"]
    assert m.break_build(only_medium, 7.0, "HIGHEST") == 0      # low-confidence names do not break the build
