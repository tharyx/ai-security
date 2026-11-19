import json
from pathlib import Path

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "detector")
FIX = Path(__file__).resolve().parent / "fixtures"
POP = json.loads((FIX / "popular.json").read_text())


def kinds(name):
    return {f.kind for f in d.check_name(name, POP)}


def test_levenshtein_basics():
    assert d.levenshtein("kitten", "sitting") == 3
    assert d.levenshtein("abc", "abc") == 0
    assert d.levenshtein("", "abc") == 3


def test_exact_and_normalized_popular_names_are_clean():
    assert d.check_name("requests", POP) == []
    assert d.check_name("PyYAML", POP) == []
    assert d.check_name("Flask", POP) == []


def test_typosquat_edit_distance():
    assert "typosquat" in kinds("numpyy")
    assert "typosquat" in kinds("colourama")


def test_transposition():
    assert "typosquat" in kinds("reqeusts")


def test_homoglyphs():
    assert "homoglyph" in kinds("djang0")
    assert "homoglyph" in kinds("rnatplotlib")


def test_combosquat():
    assert "combosquat" in kinds("pandas-utils")
    assert "combosquat" in kinds("python-requests")
    assert "combosquat" in kinds("requests_official")


def test_brandjack():
    assert "brandjack" in kinds("aws-cli-helper")


def test_unrelated_name_is_clean():
    assert d.check_name("my-internal-widget", POP) == []


def test_parse_requirements_skips_comments_and_options():
    names = d.parse_requirements((FIX / "requirements.txt").read_text())
    assert "requests" in names and "reqeusts" in names and "-r" not in names and len(names) == 11


def test_fixture_scan_flags_exactly_the_bad_lines():
    found = d.scan_requirements((FIX / "requirements.txt").read_text(), POP)
    flagged = {f.package for f in found}
    assert flagged == {"reqeusts", "numpyy", "colourama", "djang0", "rnatplotlib", "pandas-utils", "python-requests", "aws-cli-helper"}
    assert not flagged & {"requests", "flask", "numpy"}
