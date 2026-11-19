"""Tests for the Trivy-style secret scanner (FAKE secrets only)."""

import json

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "secret_scan")


def ids(results):
    return {(r["Target"], f["RuleID"]) for r in results for f in r["Secrets"]}


def test_detects_each_rule_type():
    found = ids(s.scan_tree(s.FIXTURE))
    assert ("config/app.env", "aws-access-key-id") in found
    assert ("src/client.py", "github-pat") in found
    assert ("deploy/key.pem", "private-key") in found
    assert ("src/settings.py", "generic-secret") in found


def test_allow_paths_skip_tests_and_markdown():
    targets = {r["Target"] for r in s.scan_tree(s.FIXTURE)}
    assert "tests/test_auth.py" not in targets and "README.md" not in targets


def test_without_allow_rules_the_test_fixture_would_be_reported():
    # this is why allow rules (and later suppressions with justification) exist: fixtures look like secrets
    assert s.scan_tree(s.FIXTURE, allow_paths=[]) != s.scan_tree(s.FIXTURE)
    assert any(r["Target"] == "tests/test_auth.py" for r in s.scan_tree(s.FIXTURE, allow_paths=[]))


def test_entropy_filter_drops_placeholder_values():
    assert s.scan_text("a.py", "api_key = 'aaaaaaaaaaaaaaaaaaaaaaaa'") == []
    assert s.scan_text("a.py", "api_key = 'q9X7zLm2Rt8VbN4cHy6WpD1s'") != []


def test_matches_are_redacted():
    for r in s.scan_tree(s.FIXTURE):
        for f in r["Secrets"]:
            assert "IOSFODNN7" not in f["Match"] and "*" in f["Match"]


def test_line_numbers():
    f = s.scan_text("x.env", "A=1\nB=2\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    assert f[0]["StartLine"] == 3


def test_exit_code_and_ignore_list():
    res = s.scan_tree(s.FIXTURE)
    assert s.exit_code(res) == 1
    quiet = s.scan_tree(s.FIXTURE, ignore_ids={"aws-access-key-id", "github-pat", "private-key"})
    assert s.exit_code(quiet) == 0  # only a MEDIUM generic finding remains


def test_json_output_shape():
    doc = json.loads(s.as_json(s.scan_tree(s.FIXTURE)))
    assert doc["Results"][0]["Class"] == "secret"
