"""SCA lab tests: find vulnerable pins (direct and transitive), propose fixes, confirm the fix.

The last test checks YOUR edited my-requirements.txt. It is skipped until you change the file.

Run from the repository root:
    python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns -v
"""

from pathlib import Path

import pytest

from aisec_lab import load_lab_module

a = load_lab_module(__file__, "analyzer")
HERE = Path(__file__).resolve().parent
ORIGINAL = (HERE / "requirements.txt").read_text(encoding="utf-8")
DB = a.load_db()


def scan(text):
    return a.scan(a.parse_requirements(text), DB)


def test_version_ranges():
    assert a.in_range("1.2.0", ">=1.0.0,<1.4.2")
    assert not a.in_range("1.4.2", ">=1.0.0,<1.4.2")  # the fixed version is outside the range
    assert a.in_range("0.9", "<1.5.0")


def test_version_compare_is_numeric_not_text():
    assert a.parse_version("1.10.0") > a.parse_version("1.9.0")  # the string "1.10.0" < "1.9.0"


def test_fixture_has_direct_and_transitive_findings():
    findings = scan(ORIGINAL)
    by_pkg = {f.package: f for f in findings}
    assert {"modelhub-client", "prompt-kit", "vecdb-lite", "fastinfer"} <= set(by_pkg)
    assert by_pkg["modelhub-client"].severity == "CRITICAL" and by_pkg["modelhub-client"].via == "direct"
    assert by_pkg["wire-codec"].via in {"modelhub-client", "fastinfer"}  # found through a parent


def test_clean_package_has_no_finding():
    assert "safe-utils" not in {f.package for f in scan(ORIGINAL)}


def test_findings_are_sorted_by_severity():
    sev = [a.SEVERITY_ORDER[f.severity] for f in scan(ORIGINAL)]
    assert sev == sorted(sev, reverse=True)


def test_proposed_fix_is_the_highest_fixed_version_for_the_package():
    fixes = a.propose_fixes(scan(ORIGINAL))
    assert fixes["modelhub-client"] == "1.4.2" and fixes["wire-codec"] == "1.5.0"


def test_fixed_requirements_scan_clean_and_nothing_is_downgraded():
    findings = scan(ORIGINAL)
    fixed = a.apply_fixes(ORIGINAL, a.propose_fixes(findings))
    assert scan(fixed) == []
    assert a.downgrades(ORIGINAL, fixed) == []
    assert "safe-utils==1.0.0" in fixed  # unrelated lines are untouched
    assert "wire-codec==1.5.0" in fixed  # transitive fix added as a constraint


def test_command_line_returns_failure_for_the_vulnerable_file():
    assert a.main([str(HERE / "requirements.txt")]) == 1


def test_learner_file_is_clean():
    mine = (HERE / "my-requirements.txt").read_text(encoding="utf-8")
    if mine == ORIGINAL:
        pytest.skip("exercise not started: edit my-requirements.txt")
    assert scan(mine) == [], [str(f) for f in scan(mine)]
    assert a.downgrades(ORIGINAL, mine) == [], "a fix must not downgrade a package"
    assert {r.name for r in a.parse_requirements(ORIGINAL)} <= {r.name for r in a.parse_requirements(mine)}, \
        "do not delete a dependency to make the scan pass"
