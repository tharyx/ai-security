"""Tests: vet a benign and a malicious-style skill package (fixtures are never executed)."""

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "vet")
FIX = Path(__file__).resolve().parent / "fixtures"


def checks(result):
    return {f.check for f in result["findings"]}


@pytest.fixture
def benign_copy():
    with tempfile.TemporaryDirectory() as t:
        dst = Path(t) / "notes-helper"
        shutil.copytree(FIX / "notes-helper", dst)
        yield dst


def test_benign_skill_is_allowed():
    r = v.vet(FIX / "notes-helper")
    assert r["verdict"] == "ALLOW" and r["findings"] == []


def test_malicious_sample_is_blocked_with_every_expected_finding():
    r = v.vet(FIX / "githuub-helper")
    assert r["verdict"] == "BLOCK"
    assert {"install-script", "obfuscation", "endpoint", "credential-path", "typosquat",
            "publisher-age", "hash", "signature"} <= checks(r)


def test_typosquat_distance():
    assert v.edit_distance("githuub-helper", "github-helper") == 1
    assert v.check_names({"name": "github-helper"}) == []        # exact name is not a squat
    assert v.check_names({"name": "totally-different"}) == []


def test_publisher_age_threshold():
    assert v.check_publisher({"publisher": {"created": "2026-11-12"}})
    assert v.check_publisher({"publisher": {"created": "2024-03-01"}}) == []
    assert v.check_publisher({"publisher": {}})                   # missing date is a finding


def test_tampering_a_file_after_signing_is_critical(benign_copy):
    (benign_copy / "scripts" / "summarize.py").write_text("print('changed')\n")
    r = v.vet(benign_copy)
    assert any(f.check == "hash" and f.severity == "critical" for f in r["findings"])
    assert r["verdict"] == "BLOCK"


def test_adding_an_unlisted_file_is_flagged(benign_copy):
    (benign_copy / "scripts" / "extra.py").write_text("print('x')\n")
    assert "hash" in checks(v.vet(benign_copy))


def test_bad_signature_is_critical(benign_copy):
    m = json.loads((benign_copy / "manifest.json").read_text())
    m["version"] = "9.9.9"                                        # signed fields changed
    (benign_copy / "manifest.json").write_text(json.dumps(m))
    r = v.vet(benign_copy)
    assert any(f.check == "signature" and f.severity == "critical" for f in r["findings"])


def test_untrusted_publisher_key_is_flagged(benign_copy):
    m = json.loads((benign_copy / "manifest.json").read_text())
    m["publisher"]["id"] = "someone-else"
    (benign_copy / "manifest.json").write_text(json.dumps(m))
    assert "signature" in checks(v.vet(benign_copy))


def test_unknown_url_is_flagged_but_allowed_host_is_not(benign_copy):
    s = benign_copy / "scripts" / "summarize.py"
    s.write_text(s.read_text() + "\nURL = 'https://api.github.com/x'\n")
    findings = v.check_content(benign_copy, {})
    assert not any(f.check == "endpoint" for f in findings)
    s.write_text(s.read_text() + "\nURL2 = 'http://evil.attacker.example/x'\n")
    assert any(f.check == "endpoint" for f in v.check_content(benign_copy, {}))


def test_install_script_alone_means_review_not_block(benign_copy):
    (benign_copy / "scripts" / "setup.sh").write_text("echo hello\n")
    m = json.loads((benign_copy / "manifest.json").read_text())
    m["files"] = v.file_hashes(benign_copy)
    m["signature"] = v.sign(m, v.TRUSTED_KEYS["acme-tools"])
    (benign_copy / "manifest.json").write_text(json.dumps(m))
    r = v.vet(benign_copy)
    assert r["verdict"] == "REVIEW" and checks(r) == {"install-script"}


def test_vetter_never_executes_the_sample():
    # the decoy blob would print this if it ran; the vetter only reads text
    r = v.vet(FIX / "githuub-helper")
    assert r["name"] == "githuub-helper"
