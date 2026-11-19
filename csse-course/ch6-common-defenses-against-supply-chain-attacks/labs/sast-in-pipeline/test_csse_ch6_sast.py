"""Tests for the SAST pipeline stage."""

import json

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "sast_stage")


def rule_ids(src):
    return {f["ruleId"] for f in s.analyze("a.py", src)}


def test_vulnerable_app_triggers_all_six_rules():
    assert rule_ids(s.VULNERABLE_APP) == set(s.RULES)


def test_safe_app_is_clean():
    assert s.analyze("a.py", s.SAFE_APP) == []


def test_stage_fails_on_high_and_passes_on_fixed():
    assert s.run_stage({"a.py": s.VULNERABLE_APP})["status"] == "failed"
    assert s.run_stage({"a.py": s.SAFE_APP})["status"] == "passed"


def test_fail_on_threshold_critical_only():
    only_medium = "import hashlib\nhashlib.md5(b'x')\n"
    assert s.run_stage({"a.py": only_medium}, fail_on="high")["status"] == "passed"
    assert s.run_stage({"a.py": only_medium}, fail_on="medium")["status"] == "failed"


def test_baseline_ignores_known_findings_even_when_lines_shift():
    base = {s.fingerprint(f) for f in s.analyze("app.py", s.VULNERABLE_APP)}
    shifted = "# comment\n" + s.VULNERABLE_APP
    assert s.run_stage({"app.py": shifted}, baseline=base)["status"] == "passed"


def test_baseline_still_fails_on_new_finding():
    base = {s.fingerprint(f) for f in s.analyze("app.py", s.VULNERABLE_APP)}
    r = s.run_stage({"app.py": s.VULNERABLE_APP + "\ndef more(x):\n    return exec(x)\n"}, baseline=base)
    assert r["status"] == "failed" and len(r["new"]) == 1


def test_shell_false_is_not_flagged_and_yaml_loader_kw_ok():
    assert rule_ids("import subprocess, yaml\nsubprocess.run(['a'], shell=False)\nyaml.load('x', Loader=yaml.SafeLoader)\n") == set()


def test_short_or_non_secret_constants_not_flagged():
    assert rule_ids("PASSWORD = 'x'\nNAME = 'a-long-constant-value'\n") == set()


def test_sarif_shape():
    doc = json.loads(s.run_stage({"a.py": s.VULNERABLE_APP})["sarif"])
    assert doc["version"] == "2.1.0" and doc["runs"][0]["results"][0]["partialFingerprints"]["primary"]
