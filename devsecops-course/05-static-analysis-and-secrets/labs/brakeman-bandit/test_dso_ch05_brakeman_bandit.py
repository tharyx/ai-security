import json
import tempfile
from pathlib import Path

from aisec_lab import load_lab_module

bb = load_lab_module(__file__, "brakeman_bandit")
FIX = Path(__file__).resolve().parent / "fixtures"
RB, IGNORED = bb.from_brakeman(FIX / "brakeman.json")
PY = bb.from_bandit_like(FIX / "pyapp")


def test_brakeman_report_is_normalised_with_cwe_and_confidence():
    sql = next(f for f in RB if f.title == "SQL Injection")
    assert (sql.cwe, sql.severity, sql.confidence, sql.line, sql.language) == (89, "HIGH", "HIGH", 14, "ruby")
    mass = next(f for f in RB if f.title == "Mass Assignment")
    assert mass.confidence == "LOW" and mass.cwe == 915       # Brakeman "Weak" confidence


def test_template_and_method_locations_both_work():
    assert len(RB) == 6 and len(IGNORED) == 1
    assert all(f.fingerprint for f in RB) and len({f.fingerprint for f in RB}) == 6


def test_bandit_like_findings_on_python_fixture():
    got = {f.rule for f in PY}
    assert {"B506", "B324", "B602", "B101"} <= got
    assert not any(f.rule == "B602" and "rm" in f.path for f in PY)
    shell = [f for f in PY if f.rule == "B602"]
    assert len(shell) == 1                                    # shell=False is not reported


def test_both_tools_share_one_schema():
    a, b = RB[0], PY[0]
    assert set(vars(a)) == set(vars(b))
    assert {f.tool for f in RB + PY} == {"brakeman", "bandit-like"}


def test_merge_sorts_by_score_and_dedupes_fingerprints():
    merged = bb.merge(RB, PY, RB)
    assert len(merged) == len(RB) + len(PY)
    assert [f.score for f in merged] == sorted((f.score for f in merged), reverse=True)


def test_group_by_cwe_spans_languages():
    g = bb.by_cwe(bb.merge(RB, PY))
    assert {f.language for f in g[78]} == {"ruby", "python"}       # command injection in both


def test_gate_uses_score_and_baseline():
    merged = bb.merge(RB, PY)
    assert bb.gate(merged, 6) == 1
    assert bb.gate(merged, 6, {f.fingerprint for f in merged}) == 0
    assert bb.gate([f for f in merged if f.score < 6], 6) == 0


def test_fingerprint_ignores_line_numbers():
    f = RB[0]
    shifted = json.loads((FIX / "brakeman.json").read_text())
    shifted["warnings"][0]["line"] += 50
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "b.json"
        p.write_text(json.dumps(shifted))
        moved, _ = bb.from_brakeman(p)
    assert moved[0].line == f.line + 50 and moved[0].fingerprint == f.fingerprint


def test_json_export_roundtrips():
    data = json.loads(bb.to_json(bb.merge(RB, PY)))
    assert len(data) == 10 and {"tool", "cwe", "fingerprint"} <= set(data[0])
