from pathlib import Path

from aisec_lab import load_lab_module

sc = load_lab_module(__file__, "scanner")
FIX = Path(__file__).resolve().parent / "fixtures"
VULN = (FIX / "vulnerable_app.py").read_text()
FIXED = (FIX / "fixed_app.py").read_text()


def rules(src):
    return {f.rule for f in sc.scan_source(src)}


def test_vulnerable_app_triggers_every_rule():
    assert rules(VULN) == {f"SAST{n:03d}" for n in range(1, 13)}


def test_fixed_app_is_clean():
    assert sc.scan_source(FIXED) == []


def test_line_numbers_point_at_the_vuln():
    lines = VULN.splitlines()
    for f in sc.scan_source(VULN):
        assert "VULN" in lines[f.line - 1], f"rule {f.rule} line {f.line}: {lines[f.line - 1]}"


def test_taint_raises_sql_severity():
    tainted = 'import request\nu = request.args["i"]\ncur.execute("SELECT %s" % u)\n'
    plain = 'cur.execute("SELECT %s" % 5)\n'
    assert sc.scan_source(tainted)[0].severity == "critical"
    assert sc.scan_source(plain)[0].severity == "high"


def test_parameterized_query_not_flagged():
    assert sc.scan_source('cur.execute("SELECT * FROM t WHERE id = ?", (x,))\n') == []


def test_sanitizer_clears_taint():
    src = "u = request.args['n']\nn = int(u)\nopen(n)\n"
    assert sc.scan_source(src) == []


def test_taint_propagates_through_assignments():
    src = "a = request.args['x']\nb = a + '.txt'\nopen(b)\n"
    assert [f.rule for f in sc.scan_source(src)] == ["SAST010"]


def test_yaml_safe_load_and_loader_kw_ok():
    assert sc.scan_source("yaml.safe_load(s)\nyaml.load(s, Loader=yaml.SafeLoader)\n") == []


def test_hardcoded_secret_needs_literal():
    assert rules("password = 'hunter2hunter2'\n") == {"SAST004"}
    assert rules("password = os.environ['P']\n") == set()
    assert rules("password = ''\n") == set()


def test_gate_exit_code():
    assert sc.exit_code(sc.scan_source(VULN)) == 1
    assert sc.exit_code(sc.scan_source(FIXED)) == 0
    assert sc.exit_code(sc.scan_source("tempfile.mktemp()\n"), "high") == 0


def test_scanner_does_not_execute_code():
    src = "open('SHOULD_NOT_EXIST.canary', 'w').write('x')\n"
    sc.scan_source(src)
    assert not Path("SHOULD_NOT_EXIST.canary").exists()
