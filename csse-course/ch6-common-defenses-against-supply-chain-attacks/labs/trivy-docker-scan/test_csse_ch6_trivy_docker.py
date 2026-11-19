"""Tests for the Trivy-style image scanner."""

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "trivy_lite")


def test_all_four_found_sorted_by_severity():
    r = t.scan(t.DPKG)
    assert [x["Severity"] for x in r] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_severity_filter():
    r = t.scan(t.DPKG, severity=("HIGH", "CRITICAL"))
    assert {x["PkgName"] for x in r} == {"openssl", "zlib1g"}


def test_ignore_unfixed_drops_no_fix_vuln():
    r = t.scan(t.DPKG, ignore_unfixed=True)
    assert "zlib1g" not in {x["PkgName"] for x in r}


def test_ignore_file_ids():
    r = t.scan(t.DPKG, ignore_ids={"EXAMPLE-2026-0202"})
    assert "zlib1g" not in {x["PkgName"] for x in r}


def test_exit_code_depends_on_high_critical():
    assert t.exit_code(t.scan(t.DPKG)) == 1
    assert t.exit_code(t.scan(t.DPKG, severity=("LOW", "MEDIUM"))) == 0


def test_version_comparison_handles_debian_suffixes_and_epochs():
    assert t.vulnerable("7.88.1-10+deb12u5", "7.88.1-10+deb12u6")
    assert not t.vulnerable("7.88.1-10+deb12u6", "7.88.1-10+deb12u6")
    assert t.vulnerable("1.2.9", "1.10.0")
    assert not t.vulnerable("1:1.0", "2.0")  # epoch wins


def test_parse_dpkg_skips_removed():
    txt = t.DPKG + "\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n"
    assert "gone" not in t.parse_dpkg(txt)


def test_patched_image_is_clean():
    patched = t.DPKG.replace("3.0.13-1~deb12u1", "3.0.14-1~deb12u1").replace("deb12u5", "deb12u6").replace("5.2.15-2+b7", "5.2.15-2+b8")
    r = t.scan(patched)
    assert [x["PkgName"] for x in r] == ["zlib1g"]


def test_table_has_header_and_rows():
    assert t.table(t.scan(t.DPKG)).splitlines()[0].startswith("Library")
