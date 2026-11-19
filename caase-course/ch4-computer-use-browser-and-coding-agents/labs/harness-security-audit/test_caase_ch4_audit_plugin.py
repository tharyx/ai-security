"""Tests for the SecureClaw-style audit plugin."""

import copy
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "audit_plugin")
CFG = Path(__file__).resolve().parent / "configs"


@pytest.fixture
def insecure():
    return p.load(CFG / "insecure.json")


@pytest.fixture
def hardened():
    return p.load(CFG / "hardened.json")


def test_insecure_scores_zero_and_fails_everything(insecure):
    r = p.audit(insecure)
    assert r["score"] == 0 and r["grade"] == "F"
    assert len(r["failed"]) == len(p.CHECKS)


def test_hardened_scores_full(hardened):
    r = p.audit(hardened)
    assert r["score"] == 100 and r["grade"] == "A" and r["failed"] == []


def test_every_check_is_mapped_to_asi_and_atlas():
    for c in p.CHECKS:
        assert c.asi.startswith("ASI") and 1 <= int(c.asi[3:]) <= 10
        assert c.atlas
    assert len({c.id for c in p.CHECKS}) == len(p.CHECKS)


@pytest.mark.parametrize("path,value,check", [
    (("sandbox", "enabled"), False, "SB-01"),
    (("sandbox", "run_as_root"), True, "SB-02"),
    (("sandbox", "workspace_only"), False, "SB-03"),
    (("network", "egress_mode"), "allow_all", "NET-01"),
    (("approvals", "destructive_actions"), "never", "HITL-01"),
    (("approvals", "timeout_action"), "allow", "HITL-02"),
    (("skills", "verify_signatures"), False, "SUP-01"),
    (("skills", "auto_update"), True, "SUP-02"),
    (("logging", "tamper_evident"), False, "LOG-01"),
    (("gateway", "auth_token"), None, "GW-01"),
])
def test_breaking_one_setting_fails_exactly_that_check(hardened, path, value, check):
    cfg = copy.deepcopy(hardened)
    cfg[path[0]][path[1]] = value
    assert p.audit(cfg)["failed"] == [check]


def test_secret_in_env_is_detected_by_name(hardened):
    hardened["env"]["GITHUB_TOKEN"] = "FAKE"
    r = p.audit(hardened)
    assert r["failed"] == ["SEC-01"]
    assert "GITHUB_TOKEN" in [x for x in r["results"] if x["id"] == "SEC-01"][0]["message"]


def test_unlisted_model_provider_fails(hardened):
    hardened["models"]["providers_in_use"].append("random-proxy.example")
    assert p.audit(hardened)["failed"] == ["MOD-01"]


def test_wildcard_egress_does_not_count_as_allowlist(hardened):
    hardened["network"]["egress_allowlist"] = ["*"]
    assert "NET-01" in p.audit(hardened)["failed"]


def test_empty_config_is_safe_to_audit():
    r = p.audit({})
    assert r["score"] <= 15  # only "no secrets in env" passes by default


def test_partial_hardening_gives_a_middle_score(insecure):
    insecure["sandbox"] = {"enabled": True, "run_as_root": False, "workspace_only": True}
    r = p.audit(insecure)
    assert 0 < r["score"] < 50


def test_findings_group_by_asi(insecure):
    groups = p.by_asi(p.audit(insecure))
    assert "ASI04" in groups and groups["ASI04"] == ["SUP-01", "SUP-02"]
