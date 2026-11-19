import json
from pathlib import Path

from aisec_lab import load_lab_module

c = load_lab_module(__file__, "cis_audit")
FIX = Path(__file__).parent / "fixtures"
BAD = c.audit(json.loads((FIX / "bundle_bad.json").read_text()))
GOOD = c.audit(json.loads((FIX / "bundle_good.json").read_text()))


def failed(res):
    return {r.id for r in res if not r.passed}


def test_good_bundle_passes_everything():
    assert failed(GOOD) == set()
    assert c.score(GOOD) == 100.0 and c.exit_code(GOOD) == 0


def test_bad_bundle_key_failures():
    f = failed(BAD)
    assert {"1.2.2", "2.5", "2.6", "3.16", "4.1", "5.3", "5.4", "5.15", "5.31"} <= f
    assert c.exit_code(BAD) == 1 and c.score(BAD) < 30


def test_mode_check_logic():
    assert c._mode_ok("0660", "0660") and c._mode_ok("0600", "0660")
    assert not c._mode_ok("0666", "0660")


def test_tcp_with_full_tls_passes_without_tls_fails():
    assert c._tcp_without_tls({"hosts": ["tcp://0.0.0.0:2376"], "tlsverify": True, "tlscacert": "a", "tlscert": "b", "tlskey": "c"}) == []
    assert c._tcp_without_tls({"hosts": ["tcp://0.0.0.0:2376"], "tlsverify": True}) != []
    assert c._tcp_without_tls({"hosts": ["fd://"]}) == []


def test_weighted_score_penalises_high_findings_more():
    assert c.weighted_score(BAD) < c.score(BAD) + 5
    assert c.weighted_score(GOOD) == 100.0


def test_per_container_details_name_the_container():
    d = next(r for r in BAD if r.id == "5.4").details
    assert d == ["ci-agent: privileged"]


def test_sections_cover_1_to_5():
    assert list(c.by_section(BAD)) == ["1", "2", "3", "4", "5"]
