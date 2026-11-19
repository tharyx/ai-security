import json
from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

t = load_lab_module(__file__, "tlscheck")
FIX = Path(__file__).parent / "fixtures"
TODAY = date(2026, 11, 19)


def load(name):
    return json.loads((FIX / name).read_text())


def rules(cfg):
    return {f.rule for f in t.analyze(cfg, TODAY)}


def test_bad_server_has_all_planted_issues():
    assert {
        "TLS-OLD-PROTOCOL", "TLS-NO-13", "TLS-WEAK-CIPHER", "TLS-CBC-CIPHER", "TLS-NO-FORWARD-SECRECY",
        "CERT-EXPIRED", "CERT-SELF-SIGNED", "CERT-HOSTNAME-MISMATCH", "CERT-WEAK-KEY", "CERT-WEAK-SIGNATURE", "HSTS-MISSING",
    } <= rules(load("bad_server.json"))


def test_good_server_is_clean():
    found = t.analyze(load("good_server.json"), TODAY)
    assert found == [] and t.grade(found) == "A"


def test_grades():
    assert t.grade(t.analyze(load("bad_server.json"), TODAY)) == "F"  # anonymous DH suite is critical


def test_old_protocols_by_severity():
    cfg = load("good_server.json")
    cfg["protocols"] = ["SSLv3", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    sev = {f.detail.split()[0]: f.severity for f in t.analyze(cfg, TODAY) if f.rule == "TLS-OLD-PROTOCOL"}
    assert sev == {"SSLv3": "High", "TLSv1.1": "Medium"}


def test_expiry_window():
    cfg = load("good_server.json")
    cfg["cert"]["not_after"] = "2026-12-10"
    assert "CERT-EXPIRING" in rules(cfg)
    cfg["cert"]["not_after"] = "2027-12-10"
    assert "CERT-EXPIRING" not in rules(cfg)


def test_wildcard_covers_one_label_only():
    assert t.hostname_matches("api.example.test", ["*.example.test"])
    assert not t.hostname_matches("a.b.example.test", ["*.example.test"])
    assert not t.hostname_matches("example.test", ["*.example.test"])
    assert t.hostname_matches("EXAMPLE.test", ["example.test"])


def test_hostname_mismatch_detected():
    cfg = load("good_server.json")
    cfg["host"] = "other.invalid"
    assert "CERT-HOSTNAME-MISMATCH" in rules(cfg)


def test_hsts_short_max_age():
    cfg = load("good_server.json")
    cfg["http_headers"] = {"strict-transport-security": "max-age=300"}
    assert "HSTS-SHORT" in rules(cfg)


def test_findings_sorted_by_severity():
    found = t.analyze(load("bad_server.json"), TODAY)
    order = [f.severity for f in found]
    assert order == sorted(order, key=["Critical", "High", "Medium", "Low"].index)
