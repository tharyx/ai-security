import json
from pathlib import Path

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "trivy_report")
FIX = Path(__file__).parent / "fixtures"
REP = json.loads((FIX / "trivy-report.json").read_text())


def test_summary_counts():
    s = t.summary(REP)
    assert s["CRITICAL"] == 2 and s["HIGH"] == 2 and s["MEDIUM"] == 1 and s["LOW"] == 1


def test_gate_high_fails():
    ok, why = t.gate(REP)
    assert not ok and any("CVE-2099-0001" in w for w in why)


def test_gate_critical_threshold_ignores_high():
    ok, why = t.gate(REP, fail_on="CRITICAL", fail_on_secrets=False)
    assert not ok
    assert all(w.startswith("CRITICAL") for w in why)


def test_ignore_unfixed_drops_libbar():
    _, why = t.gate(REP, ignore_unfixed=True, fail_on_secrets=False)
    assert not any("CVE-2099-0002" in w for w in why)


def test_trivyignore_parsing_and_effect():
    ids = t.parse_ignore((FIX / "trivyignore.txt").read_text())
    assert ids == {"CVE-2099-0100"}
    _, why = t.gate(REP, ignore_ids=ids, fail_on_secrets=False)
    assert not any("CVE-2099-0100" in w for w in why)


def test_everything_accepted_passes():
    ids = {v["id"] for v in t.vulns(REP)}
    ok, why = t.gate(REP, ignore_ids=ids, fail_on_secrets=False)
    assert ok and why == []


def test_secret_and_misconfig_extraction():
    assert t.secrets(REP)[0]["target"] == "app/.env"
    assert {m["ID"] for m in t.misconfigs(REP)} == {"DS002", "DS026"}
