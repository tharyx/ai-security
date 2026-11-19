import copy
import json
from pathlib import Path

from aisec_lab import load_lab_module

il = load_lab_module(__file__, "inspec_lite")
HERE = Path(__file__).parent
PROFILE = il.load_profile(HERE / "profile")
GOOD = json.loads((HERE / "fixtures" / "host_compliant.json").read_text())
BAD = json.loads((HERE / "fixtures" / "host_drifted.json").read_text())


def by_id(results):
    return {r["id"]: r for r in results}


def test_profile_passes_its_own_check():
    assert il.check_profile(PROFILE) == []
    assert len(PROFILE.controls) == 13 and PROFILE.meta["name"] == "acme-linux-baseline"


def test_check_catches_structural_errors():
    broken = copy.deepcopy(PROFILE)
    broken.controls[0].impact = 3
    broken.controls[1].id = broken.controls[0].id
    broken.controls[2].describe[0]["resource"] = "nope"
    errors = " ".join(il.check_profile(broken))
    assert "impact" in errors and "duplicate" in errors and "unknown resource" in errors


def test_compliant_host_scores_100():
    s = il.summarize(il.run_profile(PROFILE, GOOD))
    assert s["failed"] == 0 and s["compliance_pct"] == 100.0 and s["risk_weighted_pct"] == 100.0


def test_drifted_host_fails_expected_controls():
    res = by_id(il.run_profile(PROFILE, BAD))
    failed = {k for k, v in res.items() if v["status"] == "failed"}
    assert {"ssh-01", "ssh-03", "ssh-04", "os-01", "os-02", "os-04", "os-05", "os-06", "docker-01", "docker-03"} <= failed
    assert res["ssh-02"]["status"] == "passed"


def test_failure_message_shows_what_was_found():
    res = by_id(il.run_profile(PROFILE, BAD))
    assert res["ssh-01"]["results"][0]["message"] == "got: yes"


def test_only_if_skips_docker_controls_without_daemon_json():
    facts = copy.deepcopy(GOOD)
    facts["files"].pop("/etc/docker/daemon.json")
    res = by_id(il.run_profile(PROFILE, facts))
    assert all(res[c]["status"] == "skipped" for c in ("docker-01", "docker-02", "docker-03"))
    assert il.summarize(list(res.values()))["skipped"] == 3


def test_missing_fact_fails_closed_for_should_and_passes_should_not():
    facts = copy.deepcopy(GOOD)
    facts["sshd_config"].pop("PermitRootLogin")
    facts["sshd_config"].pop("Ciphers")
    res = by_id(il.run_profile(PROFILE, facts))
    assert res["ssh-01"]["status"] == "failed"  # absent setting is not proof of hardening
    assert res["ssh-04"]["status"] == "passed"


def test_matchers():
    m = il.matches
    assert m("cmp", "no", "NO") and m("cmp", 0, "0") and not m("eq", 0, "0")
    assert m("be_lte", 4, "3") and not m("be_lte", 4, "x")
    assert m("be_in", ["a", "b"], "a") and m("match", "cbc", "aes-cbc") and m("include", "x", ["x"])


def test_severity_mapping_follows_inspec():
    assert [il.severity(i) for i in (0.0, 0.3, 0.5, 0.8, 1.0)] == ["none", "low", "medium", "high", "critical"]


def test_json_reporter_shape():
    doc = il.to_inspec_json(PROFILE, il.run_profile(PROFILE, BAD))
    p = doc["profiles"][0]
    assert p["name"] == "acme-linux-baseline" and p["controls"][0]["results"][0]["code_desc"]
    assert doc["statistics"]["failed"] > 0


def test_fleet_is_deterministic_and_has_20_hosts():
    a = il.generate_fleet(GOOD, 20, seed=7)
    b = il.generate_fleet(GOOD, 20, seed=7)
    assert a == b and len(a) == 20 and len({h["hostname"] for h in a}) == 20
    assert il.generate_fleet(GOOD, 20, seed=8) != a


def test_fleet_scan_summary():
    rep = il.scan_fleet(PROFILE, il.generate_fleet(GOOD, 20, seed=7))
    assert len(rep["hosts"]) == 20 and 0 < rep["fleet_average_pct"] < 100
    assert rep["top_failing"][0][1] >= rep["top_failing"][-1][1]
    skipped = [h for h in rep["hosts"] if h["summary"]["skipped"] == 3]
    assert len(skipped) == 4  # every fifth host has no Docker
    text = il.render_fleet(rep)
    assert "Fleet of 20 hosts" in text and "Failures by severity" in text


def test_clean_fleet_is_all_100():
    rep = il.scan_fleet(PROFILE, [dict(copy.deepcopy(GOOD), hostname=f"h{i}") for i in range(20)])
    assert rep["fleet_average_pct"] == 100.0 and rep["below_threshold"] == []
