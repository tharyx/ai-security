import tempfile
from pathlib import Path

import yaml

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "reqs")
FIX = Path(__file__).resolve().parent / "fixtures"
CAT = r.load_catalog(FIX / "requirements.yaml")
GOOD = r.load_config(FIX / "app_config.json")
WEAK = r.load_config(FIX / "app_config_weak.json")


def status(results):
    return {x.id: x.status for x in results}


def test_catalog_loads_with_levels():
    assert len(CAT["requirements"]) == 11
    assert all(1 <= q["level"] <= 3 for q in CAT["requirements"])


def test_good_config_passes_except_missing_check():
    s = status(r.evaluate(CAT, GOOD))
    assert s["REQ-AUTH-01"] == "PASS" and s["REQ-CRYPTO-01"] == "PASS"
    assert s["REQ-FILE-01"] == "NO_TEST"


def test_level3_requirement_is_out_of_scope_at_target_2():
    assert status(r.evaluate(CAT, GOOD))["REQ-MFA-01"] == "OUT_OF_SCOPE"
    cat3 = dict(CAT, target_level=3)
    assert status(r.evaluate(cat3, GOOD))["REQ-MFA-01"] == "NO_TEST"


def test_gate_fails_when_a_requirement_has_no_test():
    assert r.gate(r.evaluate(CAT, GOOD)) == 1


def test_gate_goes_green_when_the_check_is_added_and_passes():
    checks = dict(r.CHECKS)
    checks["upload_limits"] = lambda cfg: (cfg.get("upload", {}).get("max_bytes", 0) > 0, "ok")
    assert r.gate(r.evaluate(CAT, GOOD, checks)) == 0


def test_weak_config_fails_several_requirements():
    s = status(r.evaluate(CAT, WEAK))
    failed = {k for k, v in s.items() if v == "FAIL"}
    assert {"REQ-AUTH-01", "REQ-COMM-01", "REQ-CFG-01", "REQ-CRYPTO-01", "REQ-AUTHZ-01", "REQ-LOG-01"} <= failed


def test_missing_config_key_fails_closed():
    s = status(r.evaluate(CAT, {}))
    assert s["REQ-AUTH-01"] == "FAIL" and s["REQ-AUTHZ-01"] == "FAIL"


def test_duplicate_ids_are_rejected():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "c.yaml"
        p.write_text(yaml.safe_dump({"requirements": [{"id": "A", "level": 1, "title": "t", "threat": "x"}] * 2}))
        try:
            r.load_catalog(p)
        except ValueError:
            return
        raise AssertionError("expected ValueError")


def test_traceability_lists_each_threat_with_status():
    t = r.traceability(CAT, r.evaluate(CAT, GOOD))
    assert "REQ-AUTH-01:PASS" in t["T-01 credential guessing"]
    assert t["T-08 malicious upload"] == ["REQ-FILE-01:NO_TEST"]
