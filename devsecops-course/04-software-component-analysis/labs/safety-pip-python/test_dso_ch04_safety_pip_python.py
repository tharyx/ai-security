import tempfile
from pathlib import Path

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "pyscan")
osv = p.osv
HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"
DB = osv.load_db(HERE.parent / "_shared" / "advisories.osv.json")
REQS, WARNS = p.parse_requirements(FIX / "requirements.txt")


def test_parser_handles_pins_extras_markers_hashes_and_includes():
    by = {r.name: r for r in REQS}
    assert by["reqwise"].version == "2.18.0" and by["reqwise"].pinned
    assert "fastclean" in by and "pytest-ish" in by            # extras + -r include
    assert by["imgbox"].version == "1.1" and not by["imgbox"].pinned
    assert sum(r.name == "yamlish" for r in REQS) == 2          # once per file


def test_unpinned_requirement_produces_a_warning():
    assert any("imgbox" in w and "not pinned" in w for w in WARNS)


def test_name_normalisation_follows_pep503():
    assert p.normalize("Foo_Bar.baz") == "foo-bar-baz"


def test_scan_finds_expected_advisories_sorted_by_severity():
    f = p.scan(REQS, DB)
    assert [x.advisory for x in f] == ["DSO-OSV-0102", "DSO-OSV-0101", "DSO-OSV-0103", "DSO-OSV-0104"]


def test_same_pin_in_two_files_is_one_finding():
    ids = [x.advisory for x in p.scan(REQS, DB)]
    assert ids.count("DSO-OSV-0102") == 1


def test_fixed_version_has_no_finding():
    reqs, _ = self_reqs("reqwise==2.20.0\nyamlish==5.4.0\n")
    assert p.scan(reqs, DB) == []


def self_reqs(text):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "r.txt"
        f.write_text(text)
        return p.parse_requirements(f)


def test_called_functions_resolve_import_aliases():
    called = p.called_functions(FIX / "src")
    assert "yamlish.safe_load" in called and "pdfmake.extract" in called and "reqwise.get" in called
    assert "yamlish.unsafe_load" not in called


def test_reachability_downgrades_unused_vulnerable_function():
    keep, drop = p.reachability(p.scan(REQS, DB), DB, FIX / "src")
    assert {f.advisory for f in drop} == {"DSO-OSV-0102", "DSO-OSV-0104"}   # unsafe_load never called; imgbox never imported
    assert {f.advisory for f in keep} == {"DSO-OSV-0101", "DSO-OSV-0103"}
    assert any("unsafe_load is never called" in f.note for f in drop)
    assert any("REACHABLE" in f.note for f in keep)


def test_gates_change_with_reachability_policy():
    f = p.scan(REQS, DB)
    keep, _ = p.reachability(list(f), DB, FIX / "src")
    assert osv.gate(f, "critical") == 1          # the unreachable critical still breaks a naive gate
    assert osv.gate(keep, "critical") == 0       # reachability-aware policy lets it through
    assert osv.gate(keep, "high") == 1           # but reqwise (HIGH) still stops the build


def test_include_loop_is_ignored():
    with tempfile.TemporaryDirectory() as d:
        a, b = Path(d) / "a.txt", Path(d) / "b.txt"
        a.write_text("-r b.txt\nreqwise==1.0.0\n")
        b.write_text("-r a.txt\n")
        reqs, warns = p.parse_requirements(a)
        assert len(reqs) == 1 and any("loop" in w for w in warns)
