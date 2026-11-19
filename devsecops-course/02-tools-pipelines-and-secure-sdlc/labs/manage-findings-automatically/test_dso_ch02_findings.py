"""Tests for normalising, deduplicating, gating and ticketing findings."""

import copy
import json
from datetime import date
from pathlib import Path

from aisec_lab import load_lab_module

f = load_lab_module(__file__, "findings")
FX = Path(__file__).parent / "fixtures"
TODAY = date(2026, 11, 19)
SARIF = f.load_json(FX / "semgrep.sarif")
ZAP = f.load_json(FX / "zap-report.json")
NPM = f.load_json(FX / "npm-audit.json")
POLICY = f.load_policy(FX / "policy.yaml")
EXISTING = f.load_json(FX / "existing-tickets.json")


def process(**over):
    args = {"sarif": SARIF, "zap": ZAP, "npm": NPM, "policy": POLICY, "existing": EXISTING, "today": TODAY}
    args.update(over)
    return f.process(args["sarif"], args["zap"], args["npm"], args["policy"], args["existing"], args["today"])


# ---- parsers


def test_sarif_parser_maps_severity_from_security_severity_score():
    items = f.parse_sarif(SARIF)
    by_rule = {i["rule"]: i for i in items}
    assert by_rule["js-sql-concat"]["severity"] == "high"       # 8.1
    assert by_rule["js-weak-random"]["severity"] == "medium"    # 5.3
    assert by_rule["js-console-log"]["severity"] == "low"       # no score: level note
    assert by_rule["js-sql-concat"]["cwe"] == ["CWE-89"]
    assert len(items) == 4


def test_sarif_level_fallback_without_score():
    assert f._sarif_severity({}, "error") == "high"
    assert f._sarif_severity({}, "warning") == "medium"
    assert f._sarif_severity({"security-severity": "9.8"}, "note") == "critical"
    assert f._sarif_severity({"security-severity": "0"}, "error") == "info"


def test_zap_parser_one_finding_per_instance_with_path_only():
    items = f.parse_zap(ZAP)
    assert len(items) == 6
    sqli = [i for i in items if i["rule"] == "40018"]
    assert {i["location"] for i in sqli} == {"/api/orders"}   # query string and host dropped
    assert sqli[0]["severity"] == "high" and sqli[0]["cwe"] == ["CWE-89"]
    info = [i for i in items if i["rule"] == "10109"][0]
    assert info["severity"] == "info" and info["cwe"] == []


def test_npm_audit_parser_skips_string_via_entries():
    items = f.parse_npm_audit(NPM)
    rules = sorted(i["rule"] for i in items)
    assert rules == ["npm-1000001", "npm-1000002"]    # mkdirp only points at minimist
    lodash = [i for i in items if "lodash" in i["title"]][0]
    assert lodash["fix"] == "upgrade to lodash@4.17.21"
    assert lodash["location"] == "package:lodash"


def test_normalize_combines_all_tools():
    items = f.normalize(SARIF, ZAP, NPM)
    assert {i["tool"] for i in items} == {"semgrep", "zap", "npm-audit"}
    assert {i["kind"] for i in items} == {"sast", "dast", "sca"}
    assert f.normalize() == []


# ---- dedup


def test_dedup_merges_same_rule_and_file_ignoring_line():
    items = f.dedup(f.normalize(SARIF))
    sql = [i for i in items if i["rule"] == "js-sql-concat"]
    assert len(sql) == 1
    assert sql[0]["occurrences"] == 2 and sql[0]["lines"] == [42, 44]


def test_dedup_merges_zap_query_string_variants():
    items = f.dedup(f.normalize(zap=ZAP))
    assert len([i for i in items if i["rule"] == "40018"]) == 1
    assert len([i for i in items if i["rule"] == "10038"]) == 2   # / and /login stay separate


def test_dedup_keeps_highest_severity_and_is_sorted():
    a = f._finding("t", "sast", "r1", "x", "low", "a.js")
    b = f._finding("t", "sast", "r1", "x", "high", "a.js")
    out = f.dedup([a, b, f._finding("t", "sast", "r2", "y", "critical", "b.js")])
    assert [o["severity"] for o in out] == ["critical", "high"]


def test_dedup_is_idempotent():
    once = f.dedup(f.normalize(SARIF, ZAP, NPM))
    twice = f.dedup(once)
    assert [x["fingerprint"] for x in once] == [x["fingerprint"] for x in twice]


def test_fingerprint_is_stable_and_distinguishes_rules():
    assert f._fp("sast", "r", "a.js") == f._fp("sast", "r", "a.js")
    assert f._fp("sast", "r", "a.js") != f._fp("sast", "r2", "a.js")


# ---- waivers


def test_active_waiver_hides_finding():
    res = process()
    assert "js-weak-random" not in {x["rule"] for x in res["findings"]}
    assert [w["rule"] for w in res["waived"]] == ["js-weak-random"]


def test_expired_waiver_no_longer_hides_finding():
    res = process()
    assert [w["rule"] for w in res["expired_waivers"]] == ["10036"]
    assert "10036" in {x["rule"] for x in res["findings"]}


def test_waiver_expiring_today_is_still_valid():
    items = f.dedup(f.normalize(zap=ZAP))
    pol = [{"rule": "10036", "location": "/", "reason": "x", "expires": "2026-11-19"}]
    active, waived, expired = f.apply_waivers(items, pol, TODAY)
    assert len(waived) == 1 and expired == []


def test_waiver_needs_matching_location():
    items = f.dedup(f.normalize(zap=ZAP))
    pol = [{"rule": "10038", "location": "/", "reason": "x", "expires": "2030-01-01"}]
    active, waived, _ = f.apply_waivers(items, pol, TODAY)
    assert [w["location"] for w in waived] == ["/"]
    assert "/login" in [a["location"] for a in active if a["rule"] == "10038"]


# ---- thresholds


def test_gate_fails_on_high_findings():
    res = process()
    assert res["gate"]["passed"] is False
    assert res["gate"]["breaches"] == {"high": (3, 0)}


def test_gate_passes_when_within_limits():
    ok = f.evaluate([f._finding("t", "sast", "r", "x", "medium", "a")], {"critical": 0, "high": 0, "medium": 5})
    assert ok["passed"] and ok["breaches"] == {}


def test_gate_medium_limit_is_enforced():
    items = [f._finding("t", "sast", "r", "x", "medium", f"f{i}.js") for i in range(6)]
    res = f.evaluate(items, {"medium": 5})
    assert res["breaches"] == {"medium": (6, 5)}


def test_fixing_the_highs_flips_the_gate():
    sarif, zap, npm = copy.deepcopy(SARIF), copy.deepcopy(ZAP), copy.deepcopy(NPM)
    sarif["runs"][0]["results"] = [r for r in sarif["runs"][0]["results"] if r["ruleId"] != "js-sql-concat"]
    zap["site"][0]["alerts"] = [a for a in zap["site"][0]["alerts"] if a["name"] != "SQL Injection"]
    del npm["vulnerabilities"]["lodash"]
    assert process(sarif=sarif, zap=zap, npm=npm)["gate"]["passed"] is True


# ---- tickets


def test_tickets_created_only_for_new_findings_at_or_above_minimum():
    t = process()["tickets"]
    titles = [c["title"] for c in t["created"]]
    assert len(t["created"]) == 5
    assert not any("console.log" in x or "Server Leaks" in x or "Modern Web" in x for x in titles)
    assert any("SQL Injection" in x for x in titles)


def test_existing_open_ticket_is_not_duplicated():
    t = process()["tickets"]
    assert len(t["already_tracked"]) == 1
    assert not any("string concatenation" in c["title"] for c in t["created"])


def test_ticket_keys_continue_after_highest_existing():
    keys = [c["key"] for c in process()["tickets"]["created"]]
    assert keys == ["SEC-9", "SEC-10", "SEC-11", "SEC-12", "SEC-13"]


def test_vanished_finding_is_listed_for_closing():
    assert process()["tickets"]["to_close"] == ["SEC-8"]


def test_running_twice_creates_nothing_new():
    first = process()["tickets"]["created"]
    again = process(existing=EXISTING + first)["tickets"]
    assert again["created"] == []
    assert again["to_close"] == ["SEC-8"]


def test_closed_ticket_allows_a_new_one():
    closed = [dict(t, status="closed") for t in EXISTING]
    keys = [c["title"] for c in process(existing=closed)["tickets"]["created"]]
    assert any("string concatenation" in k for k in keys)


def test_due_dates_follow_sla():
    created = {c["severity"]: c for c in process()["tickets"]["created"]}
    assert created["high"]["due"] == "2026-12-19"     # +30
    assert created["medium"]["due"] == "2027-02-17"    # +90


def test_ticket_is_json_serialisable_with_labels():
    t = process()["tickets"]["created"][0]
    data = json.loads(json.dumps(t))
    assert "security" in data["labels"] and data["description"]["occurrences"] >= 1
