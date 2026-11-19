import datetime as dt
import json
from pathlib import Path

from aisec_lab import load_lab_module

g = load_lab_module(__file__, "gates")
FX = Path(__file__).resolve().parent / "fixtures"
KEV = set(json.loads((FX / "kev.json").read_text())["kev"])
BASELINE = json.loads((FX / "baseline.json").read_text())["suppressions"]


def load(d, name):
    return json.loads((FX / d / name).read_text())


def test_sca_parser_marks_fixable_and_known_exploited():
    f = {x.id: x for x in g.parse_sca(load("reports-before", "sca-osv.json"), KEV)}
    assert f["EXAMPLE-2026-0001"].kev and f["EXAMPLE-2026-0001"].fixable
    assert not f["EXAMPLE-2026-0003"].fixable


def test_sca_gate_fails_on_fixable_high_but_only_warns_on_unfixable():
    code, lines = g.evaluate(g.parse_sca(load("reports-before", "sca-osv.json"), KEV))
    assert code == 1
    assert any(line.startswith("[warn]") and "EXAMPLE-2026-0003" in line for line in lines)


def test_sarif_security_severity_maps_to_levels():
    f = {x.id: x for x in g.parse_sarif(load("reports-before", "sast.sarif"))}
    assert f["python.sqlalchemy.sqli.string-concat"].severity == "CRITICAL"
    assert f["python.flask.debug-enabled"].severity == "MEDIUM"
    assert f["python.logging.secret-in-log"].severity == "LOW"  # no score: falls back to level "note"
    assert f["python.jwt.verify-disabled"].where == "orders/auth.py:17"


def test_zap_high_risk_alert_fails_dast_gate():
    code, lines = g.evaluate(g.parse_zap(load("reports-before", "zap-report.json")))
    assert code == 1 and "SQL Injection" in lines[0]


def test_valid_suppression_applies_but_expired_or_ownerless_ones_do_not():
    findings = (g.parse_sca(load("reports-before", "sca-osv.json"), KEV) + g.parse_sarif(load("reports-before", "sast.sarif"))
                + g.parse_zap(load("reports-before", "zap-report.json")))
    code, lines = g.evaluate(findings, baseline=BASELINE)
    text = "\n".join(lines)
    assert "suppressed until 2027-01-31" in text and "python.jwt.verify-disabled" in text
    assert any(line.startswith("[FAIL]") and "EXAMPLE-2026-0002" in line for line in lines)  # expired
    assert any(line.startswith("[FAIL]") and "SQL Injection" in line for line in lines)  # no owner/reason
    assert code == 1


def test_suppression_stops_working_after_expiry():
    findings = g.parse_sarif(load("reports-before", "sast.sarif"))
    _, lines = g.evaluate(findings, baseline=BASELINE, today=dt.date(2027, 2, 1))
    assert any(line.startswith("[FAIL]") and "verify-disabled" in line for line in lines)


def test_fixed_reports_pass_all_gates():
    findings = (g.parse_sca(load("reports-after", "sca-osv.json"), KEV) + g.parse_sarif(load("reports-after", "sast.sarif"))
                + g.parse_zap(load("reports-after", "zap-report.json")))
    code, lines = g.evaluate(findings, baseline=BASELINE)
    assert code == 0 and all(not line.startswith("[FAIL]") for line in lines)


def test_pipeline_blocks_prod_deploy_when_gates_fail():
    runner = g.embed_in_pipeline(FX / "reports-before", BASELINE, KEV)
    r = runner.run(runner.load(FX / "secure-pipeline.json"), branch="main")
    assert r.jobs["sca"].status == "failed" and r.jobs["sast"].status == "failed"
    assert r.jobs["dast"].status == "skipped" and r.jobs["deploy-prod"].status == "skipped"


def test_pipeline_passes_and_publishes_reports_after_fixes():
    runner = g.embed_in_pipeline(FX / "reports-after", BASELINE, KEV)
    r = runner.run(runner.load(FX / "secure-pipeline.json"), branch="main")
    assert r.status == "passed" and "gl-sca-report.json" in r.jobs["sca"].artifacts
    assert r.jobs["deploy-prod"].status == "success"
