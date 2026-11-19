import copy
from pathlib import Path

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "validate")
FIX = Path(__file__).parent / "fixtures"
GOOD = v.load(FIX / "good.yaml")
BROKEN = v.load(FIX / "broken.yaml")


def codes(docs):
    return {i.code for i in v.validate(docs)}


def test_good_set_has_no_issues():
    assert v.validate(GOOD) == []


def test_broken_set_codes():
    assert {"WK-001", "WK-002", "WK-003", "WK-011", "WK-012", "WK-020", "WK-021", "WK-023"} <= codes(BROKEN)


def test_named_target_port_is_resolved():
    assert "WK-011" not in codes(GOOD)


def test_wrong_target_port_is_caught():
    docs = copy.deepcopy(GOOD)
    docs[1]["spec"]["ports"][0]["targetPort"] = 9090
    assert "WK-011" in codes(docs)


def test_selector_mismatch_leaves_service_without_endpoints():
    docs = copy.deepcopy(GOOD)
    docs[1]["spec"]["selector"] = {"app": "other"}
    assert "WK-010" in codes(docs)


def test_ingress_backend_port_must_exist():
    docs = copy.deepcopy(GOOD)
    docs[2]["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["port"] = {"number": 8443}
    assert "WK-022" in codes(docs)


def test_removing_tls_is_high():
    docs = copy.deepcopy(GOOD)
    del docs[2]["spec"]["tls"]
    assert [i.severity for i in v.validate(docs) if i.code == "WK-020"] == ["HIGH"]


def test_services_in_other_namespaces_are_not_matched():
    docs = copy.deepcopy(GOOD)
    docs[1]["metadata"]["namespace"] = "other"
    assert "WK-010" in codes(docs)
