import copy
import json
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "pdp")
FIX = Path(__file__).resolve().parent / "fixtures"
POLICY = p.load_policy(FIX / "policy.json")
ALICE = {"id": "u-alice", "roles": ["rider"]}


def test_all_policy_unit_tests_pass():
    cases = json.loads((FIX / "policy_tests.json").read_text(encoding="utf-8"))
    assert p.run_policy_tests(POLICY, cases) == []


def test_default_deny_when_no_rule_matches():
    d = p.decide(POLICY, {"id": "u-x", "roles": []}, "trip:refund", {"owner_id": "u-x"})
    assert d.allow is False and "default deny" in d.reason


def test_pep_blocks_bola_and_allows_owner():
    assert p.pep_get_trip(POLICY, ALICE, "t-1")[0] == 200
    status, body, d = p.pep_get_trip(POLICY, ALICE, "t-2")
    assert status == 403 and body is None


def test_explicit_deny_overrides_admin_allow():
    d = p.decide(POLICY, {"id": "r", "roles": ["admin"], "suspended": True}, "trip:read", {"owner_id": "u-bob"})
    assert d.allow is False and d.matched == ["deny-suspended"]


def test_policy_change_changes_behaviour_without_code_change():
    sam = {"id": "u-sam", "roles": ["support"], "region": "south"}
    assert p.pep_get_trip(POLICY, sam, "t-1")[0] == 200
    stricter = copy.deepcopy(POLICY)
    stricter["rules"] = [r for r in stricter["rules"] if r["id"] != "support-reads-trips-in-own-region"]
    assert p.pep_get_trip(stricter, sam, "t-1")[0] == 403


def test_hardcoded_and_pdp_agree_on_basic_cases():
    for trip in ("t-1", "t-2"):
        assert p.hardcoded_get_trip(ALICE, trip)[0] == p.pep_get_trip(POLICY, ALICE, trip)[0]


def test_lint_rejects_typo_operator_and_duplicate_ids():
    with pytest.raises(p.PolicyError):
        p.lint({"default": "deny", "rules": [{"id": "a", "effect": "allow", "actions": ["*"], "when": [["x", "=", "y"]]}]})
    with pytest.raises(p.PolicyError):
        p.lint({"default": "deny", "rules": [{"id": "a", "effect": "allow", "actions": ["*"]},
                                             {"id": "a", "effect": "deny", "actions": ["*"]}]})


def test_missing_attribute_does_not_crash_or_allow():
    d = p.decide(POLICY, {"id": "u-z"}, "trip:read", {"owner_id": "u-bob"})
    assert d.allow is False
