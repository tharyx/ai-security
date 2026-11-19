from pathlib import Path

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "sca")
FIX = Path(__file__).resolve().parent / "fixtures"
DEPS, ADV = s.load(FIX / "requirements.lock", FIX / "advisories.json")


def test_parse_lock_direct_and_transitive():
    by = {d.name: d for d in DEPS}
    assert len(DEPS) == 6
    assert by["examplelib"].direct and by["yaml-lite"].via == "examplelib" and not by["yaml-lite"].direct


def test_version_range_logic():
    r = [{"introduced": "1.0.0", "fixed": "1.4.2"}]
    assert s.is_affected("1.3.0", r) and s.is_affected("1.0.0", r)
    assert not s.is_affected("1.4.2", r) and not s.is_affected("0.9.9", r)
    assert s.is_affected("1.10.0", [{"introduced": "1.2.0"}])  # no fix yet; numeric, not string, compare


def test_scan_finds_expected_advisories_sorted_by_severity():
    f = s.scan(DEPS, ADV)
    assert [x.advisory for x in f] == ["EXAMPLE-2026-0002", "EXAMPLE-2026-0001", "EXAMPLE-2026-0004"]
    assert not {"EXAMPLE-2026-0003", "EXAMPLE-2026-0005"} & {x.advisory for x in f}  # fixed versions in use


def test_transitive_finding_reports_parent_and_fix():
    f = {x.advisory: x for x in s.scan(DEPS, ADV)}
    assert f["EXAMPLE-2026-0002"].via == "examplelib" and f["EXAMPLE-2026-0002"].fixed_in == "0.6.0"
    assert f["EXAMPLE-2026-0001"].direct


def test_ignore_list_suppresses_with_reason():
    f = s.scan(DEPS, ADV, ignore={"EXAMPLE-2026-0002": "not reachable, reviewed 2026-01"})
    assert "EXAMPLE-2026-0002" not in {x.advisory for x in f}


def test_gate_threshold():
    f = s.scan(DEPS, ADV)
    assert s.exit_code(f, "high") == 1
    assert s.exit_code(f, "critical") == 1
    only_low = [x for x in f if x.severity == "low"]
    assert s.exit_code(only_low, "high") == 0


def test_clean_lock_passes():
    deps = s.parse_lock("examplelib==1.4.2\nyaml-lite==0.6.0\n")
    assert s.scan(deps, ADV) == []
