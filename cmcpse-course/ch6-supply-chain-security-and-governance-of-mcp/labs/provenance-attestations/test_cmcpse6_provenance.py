"""Provenance lab tests: statement shape, DSSE signing, and a deploy gate for builder identity and source repo.

Run from the repository root:
    python -m pytest cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations -v
"""

import base64
import copy
import json
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

p = load_lab_module(__file__, "provenance")
BUILDER = "https://ci.example.internal/builders/mcp-release@v1"
REPO = "https://git.example.internal/acme/notes-mcp"
KEYS = {"lab-attest-1": p.LAB_KEY}
POLICY = p.Policy({BUILDER}, REPO, {"refs/heads/main"}, {".ci/release.yml"})
WORK = Path(tempfile.mkdtemp())
ARTIFACT = WORK / "notes-mcp-1.2.0.tar"
ARTIFACT.write_bytes(b"pretend archive")
ARTIFACTS = {"notes-mcp-1.2.0.tar": ARTIFACT}


def statement(**overrides):
    args = dict(artifacts=ARTIFACTS, builder_id=BUILDER, repository=REPO, ref="refs/heads/main", commit="ab" * 20,
                workflow=".ci/release.yml", materials=[{"uri": "pkg:pypi/mcp-sdk-lite@1.4.0", "digest": {"sha256": "11" * 32}}],
                invocation_id="run-1")
    args.update(overrides)
    return p.make_statement(**args)


def gate(env, artifacts=ARTIFACTS, keys=KEYS, policy=POLICY):
    return p.deploy_gate(env, artifacts, keys, policy)


# ------------------------------------------------------------------ statement shape
def test_statement_is_in_toto_v1_with_slsa_provenance_predicate():
    s = statement()
    assert s["_type"] == "https://in-toto.io/Statement/v1" and s["predicateType"] == "https://slsa.dev/provenance/v1"
    assert s["subject"][0]["digest"]["sha256"] == p.sha256_file(ARTIFACT)
    assert s["predicate"]["runDetails"]["builder"]["id"] == BUILDER
    assert s["predicate"]["buildDefinition"]["externalParameters"]["repository"] == REPO


def test_materials_include_the_source_commit_and_dependencies():
    deps = statement()["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert deps[0]["digest"]["gitCommit"] == "ab" * 20 and deps[1]["uri"].startswith("pkg:pypi/")


# ------------------------------------------------------------------ DSSE envelope
def test_envelope_round_trip():
    env = p.sign_statement(statement())
    assert env["payloadType"] == p.PAYLOAD_TYPE
    assert p.verify_envelope(env, KEYS)["predicateType"] == p.PREDICATE_TYPE


def test_pae_matches_the_dsse_definition():
    assert p.pae("t", b"xy") == b"DSSEv1 1 t 2 xy"


def test_payload_tamper_breaks_the_signature():
    env = p.sign_statement(statement())
    doc = json.loads(base64.b64decode(env["payload"]))
    doc["predicate"]["runDetails"]["builder"]["id"] = "https://evil.example"
    env["payload"] = base64.b64encode(json.dumps(doc, sort_keys=True).encode()).decode()
    with pytest.raises(p.ProvenanceError):
        p.verify_envelope(env, KEYS)


def test_payload_type_is_part_of_the_signature():
    env = p.sign_statement(statement())
    env["payloadType"] = "text/plain"
    with pytest.raises(p.ProvenanceError):
        p.verify_envelope(env, KEYS)


def test_unknown_key_and_malformed_envelope_are_rejected():
    env = p.sign_statement(statement(), keyid="attacker")
    with pytest.raises(p.ProvenanceError):
        p.verify_envelope(env, KEYS)
    with pytest.raises(p.ProvenanceError, match="malformed"):
        p.verify_envelope({"payload": "!!!"}, KEYS)


# ------------------------------------------------------------------ the deploy gate
def test_good_build_passes_the_gate():
    r = gate(p.sign_statement(statement()))
    assert r.ok and r.reasons == []


def test_artifact_swapped_after_build_is_rejected():
    evil = WORK / "evil.tar"
    evil.write_bytes(b"swapped")
    r = gate(p.sign_statement(statement()), {"notes-mcp-1.2.0.tar": evil})
    assert not r.ok and "does not match the attested digest" in r.reasons[0]


def test_artifact_not_in_the_attestation_is_rejected():
    extra = WORK / "extra.tar"
    extra.write_bytes(b"x")
    r = gate(p.sign_statement(statement()), {"extra.tar": extra})
    assert r.reasons == ["artifact extra.tar is not covered by the attestation"]


def test_builder_identity_must_be_trusted():
    r = gate(p.sign_statement(statement(builder_id="https://laptop.example/builder")))
    assert not r.ok and "is not trusted" in r.reasons[0]


def test_source_repository_must_match_so_fork_builds_are_rejected():
    r = gate(p.sign_statement(statement(repository="https://git.example.internal/mallory/notes-mcp")))
    assert not r.ok and any("expected" in x for x in r.reasons)


def test_only_allowed_refs_may_produce_release_artifacts():
    r = gate(p.sign_statement(statement(ref="refs/heads/feature-x")))
    assert any("ref refs/heads/feature-x" in x for x in r.reasons)


def test_unexpected_workflow_is_rejected():
    r = gate(p.sign_statement(statement(workflow=".ci/custom.yml")))
    assert any("unexpected build workflow" in x for x in r.reasons)


def test_unpinned_material_is_rejected():
    r = gate(p.sign_statement(statement(materials=[{"uri": "pkg:pypi/yamlish@latest", "digest": {}}])))
    assert any("not pinned by digest" in x for x in r.reasons)


def test_forged_statement_signed_with_the_wrong_key_is_rejected():
    r = gate(p.sign_statement(statement(), key=b"FAKE-attacker"))
    assert not r.ok and r.reasons == ["no valid signature from a trusted key"]


def test_replaying_an_old_attestation_for_a_new_artifact_fails():
    old_env = p.sign_statement(statement())
    new = WORK / "notes-mcp-1.2.0.tar"
    original = new.read_bytes()
    try:
        new.write_bytes(b"version 1.3.0 contents")
        assert not gate(old_env, {"notes-mcp-1.2.0.tar": new}).ok
    finally:
        new.write_bytes(original)


def test_gate_reports_all_problems_at_once():
    s = statement(builder_id="https://x", repository="https://y", ref="refs/heads/z")
    assert len(gate(p.sign_statement(s)).reasons) >= 3
