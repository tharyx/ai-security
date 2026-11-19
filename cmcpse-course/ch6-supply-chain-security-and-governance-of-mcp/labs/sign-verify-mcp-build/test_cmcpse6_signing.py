"""Sign-and-verify lab tests: a good build deploys, every kind of tampering is refused.

Run from the repository root:
    python -m pytest cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build -v
"""

import copy
import shutil
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "signing")
SRC = Path(__file__).resolve().parent / "fixtures" / "build_src"
KEYS = {"lab-key-1": s.LAB_KEY}


@pytest.fixture()
def shipped():
    work = Path(tempfile.mkdtemp())
    target = work / "deploy"
    shutil.copytree(SRC, target)
    bundle = s.sign(s.build_manifest(SRC, "notes-mcp", "1.2.0"))
    return bundle, target


def test_manifest_lists_every_file_with_a_sha256():
    m = s.build_manifest(SRC, "notes-mcp", "1.2.0")
    assert set(m["files"]) == {"server.py", "mcp-manifest.json", "requirements.lock"}
    assert all(len(h) == 64 for h in m["files"].values())


def test_canonical_form_is_stable_regardless_of_key_order():
    assert s.canonical({"b": 1, "a": 2}) == s.canonical({"a": 2, "b": 1})


def test_good_build_deploys(shipped):
    bundle, target = shipped
    assert s.deploy(bundle, target, KEYS, expected_name="notes-mcp", min_version="1.1.0") == "deployed notes-mcp 1.2.0"


def test_changed_file_is_detected(shipped):
    bundle, target = shipped
    (target / "server.py").write_text("backdoor")
    r = s.verify_bundle(bundle, target, KEYS)
    assert not r.ok and r.problems == ["content changed after signing: server.py"]


def test_added_file_is_detected(shipped):
    bundle, target = shipped
    (target / "new_tool.py").write_text("x")
    assert s.verify_bundle(bundle, target, KEYS).problems == ["unlisted file present (not signed): new_tool.py"]


def test_deleted_file_is_detected(shipped):
    bundle, target = shipped
    (target / "requirements.lock").unlink()
    assert s.verify_bundle(bundle, target, KEYS).problems == ["missing file: requirements.lock"]


def test_manifest_edit_breaks_the_signature(shipped):
    bundle, target = shipped
    forged = copy.deepcopy(bundle)
    forged["manifest"]["files"]["server.py"] = s.sha256_bytes(b"evil")
    (target / "server.py").write_text("evil")
    assert s.verify_bundle(forged, target, KEYS).problems == ["signature does not match the manifest"]


def test_signature_edit_is_rejected(shipped):
    bundle, target = shipped
    bad = dict(bundle, signature="0" * 64)
    assert not s.verify_bundle(bad, target, KEYS).ok


def test_wrong_key_and_unknown_key_id_are_rejected(shipped):
    bundle, target = shipped
    assert not s.verify_bundle(bundle, target, {"lab-key-1": b"FAKE-other-key"}).ok
    unknown = dict(bundle, key_id="attacker-key")
    assert "unknown signing key id" in s.verify_bundle(unknown, target, KEYS).problems[0]


def test_rollback_to_an_older_signed_version_is_refused(shipped):
    _, target = shipped
    old = s.sign(s.build_manifest(SRC, "notes-mcp", "1.0.0"))
    r = s.verify_bundle(old, target, KEYS, min_version="1.1.0")
    assert r.problems == ["rollback: version 1.0.0 is older than 1.1.0"]


def test_numeric_version_compare():
    assert s.version_tuple("1.10.0") > s.version_tuple("1.9.0")


def test_wrong_package_name_is_refused(shipped):
    bundle, target = shipped
    assert not s.verify_bundle(bundle, target, KEYS, expected_name="other-mcp").ok


def test_manifest_path_traversal_is_refused():
    work = Path(tempfile.mkdtemp())
    (work / "deploy").mkdir()
    (work / "outside.txt").write_text("x")
    manifest = {"schema": s.SCHEMA, "name": "n", "version": "1.0.0", "builder": "b", "files": {"../outside.txt": s.sha256_bytes(b"x")}}
    r = s.verify_bundle(s.sign(manifest), work / "deploy", KEYS)
    assert any("escapes the deploy folder" in p for p in r.problems)


def test_deploy_raises_on_any_problem(shipped):
    bundle, target = shipped
    (target / "server.py").write_text("x")
    with pytest.raises(PermissionError, match="deploy refused"):
        s.deploy(bundle, target, KEYS)


def test_hmac_limitation_whoever_can_verify_can_forge(shipped):
    """Why real signing uses asymmetric keys: the verifier's key is enough to mint a valid signature."""
    _, target = shipped
    (target / "server.py").write_text("evil")
    forged_manifest = s.build_manifest(target, "notes-mcp", "9.9.9")
    forged = s.sign(forged_manifest, key=KEYS["lab-key-1"])  # an insider with the deploy-side key
    assert s.verify_bundle(forged, target, KEYS).ok
