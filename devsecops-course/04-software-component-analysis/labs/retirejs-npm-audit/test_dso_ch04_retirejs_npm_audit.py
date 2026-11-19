import json
from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

j = load_lab_module(__file__, "jsscan")
osv = j.osv
HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"
DB = osv.load_db(HERE.parent / "_shared" / "advisories.osv.json")
LOCK = j.load_lock(FIX / "package-lock.json")
EXT = j.load_extractors(FIX / "retire_extractors.json")


def test_version_compare_is_numeric_not_string():
    assert osv.vkey("1.10.0") > osv.vkey("1.9.0")
    assert osv.vkey("1.0") == osv.vkey("1.0.0")
    assert osv.vkey("2.0.0-rc1") < osv.vkey("2.0.0")


def test_osv_range_introduced_and_fixed():
    r = [{"events": [{"introduced": "2.0.0"}, {"fixed": "2.1.5"}]}]
    assert osv.in_ranges("2.1.0", r) and not osv.in_ranges("2.1.5", r) and not osv.in_ranges("1.9.9", r)


def test_npm_audit_finds_direct_and_transitive_with_path():
    f = {x.advisory: x for x in j.npm_audit(LOCK, DB)}
    assert set(f) == {"DSO-OSV-0001", "DSO-OSV-0002", "DSO-OSV-0003"}
    assert f["DSO-OSV-0001"].direct and not f["DSO-OSV-0002"].direct
    assert f["DSO-OSV-0002"].path == ["(root)", "webkit-lite", "acme-templ"]


def test_fixed_package_version_is_not_reported():
    assert "DSO-OSV-0005" not in {x.advisory for x in j.npm_audit(LOCK, DB)}   # webkit-lite 4.5.0 > 4.2.0 fix


def test_fix_notes_say_whether_the_fix_is_breaking():
    f = {x.advisory: x for x in j.npm_audit(LOCK, DB)}
    assert "inside your declared range" in f["DSO-OSV-0002"].note
    assert "MAJOR" in f["DSO-OSV-0003"].note        # tinyparse ^0.9.0 -> fix 1.0.0


def test_omit_dev_drops_dev_only_findings():
    ids = {x.advisory for x in j.npm_audit(LOCK, DB, omit_dev=True)}
    assert "DSO-OSV-0003" not in ids and "DSO-OSV-0001" in ids


def test_retire_identifies_by_filename_banner_and_renamed_file():
    root = FIX / "webapp" / "static" / "js"
    assert j.identify(root / "fakequery-1.8.2.min.js", EXT) == [("fakequery", "1.8.2", "filename+filecontent")]
    assert j.identify(root / "vendor" / "bundle.js", EXT) == [("chartlet", "3.0.1", "filecontent")]
    assert j.identify(root / "old" / "fq.js", EXT) == [("fakequery", "1.9.1", "filecontent")]
    assert j.identify(root / "app.js", EXT) == []


def test_retire_scan_reports_only_vulnerable_versions():
    got = {(f.package, f.version, f.advisory) for f in j.retire_scan(FIX / "webapp", EXT, DB)}
    assert got == {("fakequery", "1.8.2", "DSO-OSV-0001"), ("chartlet", "3.0.1", "DSO-OSV-0004")}


def test_tools_complement_each_other():
    c = j.compare(j.retire_scan(FIX / "webapp", EXT, DB), j.npm_audit(LOCK, DB))
    assert ("chartlet", "DSO-OSV-0004") in c["retire_only"]       # copied file, not in the lock file
    assert ("acme-templ", "DSO-OSV-0002") in c["audit_only"]      # transitive, not in any JS file name
    assert ("fakequery", "DSO-OSV-0001") in c["both"]


def test_gate_thresholds_and_cvss():
    fs = j.npm_audit(LOCK, DB)
    assert osv.gate(fs, "critical") == 1
    assert osv.gate([f for f in fs if f.severity != "CRITICAL"], "critical") == 0
    assert osv.gate([f for f in fs if f.severity != "CRITICAL"], "critical", fail_cvss=7.0) == 1
    assert osv.gate([], "low") == 0 and osv.gate(fs, "critical", max_findings=2) == 1


def test_ignores_need_reason_and_unexpired_date():
    every = j.npm_audit(LOCK, DB) + j.retire_scan(FIX / "webapp", EXT, DB)
    ignores = json.loads((FIX / "ignores.json").read_text())
    kept, suppressed, warns = osv.apply_ignores(every, ignores, date(2026, 11, 19))
    assert [f.advisory for f in suppressed] == ["DSO-OSV-0003"]
    assert any("EXPIRED" in w for w in warns) and any("no reason" in w for w in warns)
    assert "DSO-OSV-0004" in {f.advisory for f in kept}
    kept2, supp2, _ = osv.apply_ignores(every, ignores, date(2025, 12, 1))
    assert "DSO-OSV-0004" in {f.advisory for f in supp2}     # valid before it expired
