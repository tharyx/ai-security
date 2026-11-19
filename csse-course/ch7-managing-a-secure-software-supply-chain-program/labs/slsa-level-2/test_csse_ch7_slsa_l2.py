import base64
import json

from aisec_lab import load_lab_module

sp = load_lab_module(__file__, "signed_provenance")

KEY = b"FAKE-BUILDER-SECRET-not-real"
BUILDER = "https://example.invalid/hosted-builder"
ART = b"fake wheel bytes"
COMMON = dict(repo_uri="https://github.com/example/app", ref="refs/tags/v1.0.0",
              commit="b" * 40, artifact_name="app.whl", artifact_bytes=ART)
POLICY = sp.Policy([sp.TrustedBuilder(BUILDER, KEY)], "https://github.com/example/app")


def hosted(**over):
    kw = dict(COMMON)
    kw.update(over)
    return sp.HostedBuilder(BUILDER, KEY).build_and_sign(**kw)


def edit(env, fn):
    stmt = json.loads(base64.b64decode(env["payload"]))
    fn(stmt)
    return dict(env, payload=base64.b64encode(json.dumps(stmt, sort_keys=True).encode()).decode())


def test_hosted_signed_provenance_is_level_2():
    v = sp.verify(hosted(), ART, POLICY)
    assert v.ok and v.level == 2 and v.reasons == []


def test_l1_only_provenance_fails_l2_policy():
    l1 = sp.self_attested(sp.make_statement(builder_id=BUILDER, **COMMON))
    v = sp.verify(l1, ART, POLICY)
    assert not v.ok
    assert v.level == 1  # still a complete L1 document
    assert any("no signature" in r for r in v.reasons)


def test_forged_signature_fails():
    env = hosted()
    env["signatures"][0]["sig"] = base64.b64encode(b"x" * 32).decode()
    v = sp.verify(env, ART, POLICY)
    assert not v.ok and any("does not verify" in r for r in v.reasons)


def test_unknown_builder_fails_even_with_valid_own_signature():
    rogue = sp.HostedBuilder("https://attacker.example/builder", b"attacker-key").build_and_sign(**COMMON)
    v = sp.verify(rogue, ART, POLICY)
    assert not v.ok and any("allowlist" in r for r in v.reasons)


def test_builder_id_claim_swapped_breaks_signature():
    # Attacker re-labels the payload as the trusted builder but cannot re-sign.
    rogue = sp.HostedBuilder("https://attacker.example/builder", b"attacker-key").build_and_sign(**COMMON)
    relabelled = edit(rogue, lambda s: s["predicate"]["runDetails"]["builder"].update(id=BUILDER))
    v = sp.verify(relabelled, ART, POLICY)
    assert not v.ok and any("does not verify" in r for r in v.reasons)


def test_artifact_digest_mismatch_fails():
    v = sp.verify(hosted(), b"evil bytes", POLICY)
    assert not v.ok and any("digest" in r for r in v.reasons)


def test_replayed_provenance_for_another_artifact_fails():
    other = hosted(artifact_bytes=b"other artifact", artifact_name="other.whl")
    assert not sp.verify(other, ART, POLICY).ok


def test_payload_edit_after_signing_fails():
    env = edit(hosted(), lambda s: s["subject"][0]["digest"].update(sha256=sp.sha256_hex(b"evil")))
    v = sp.verify(env, b"evil", POLICY)
    assert not v.ok and any("does not verify" in r for r in v.reasons)


def test_wrong_source_repo_fails():
    v = sp.verify(hosted(repo_uri="https://github.com/example/other"), ART, POLICY)
    assert not v.ok and any("expected repo" in r for r in v.reasons)


def test_repo_prefix_trick_fails():
    v = sp.verify(hosted(repo_uri="https://github.com/example/app-evil"), ART, POLICY)
    assert not v.ok


def test_non_release_ref_fails():
    v = sp.verify(hosted(ref="refs/heads/feature-x"), ART, POLICY)
    assert not v.ok and any("release ref" in r for r in v.reasons)


def test_garbage_payload():
    v = sp.verify({"payload": "!!!", "payloadType": sp.PAYLOAD_TYPE, "signatures": []}, ART, POLICY)
    assert not v.ok and v.level == 0


def test_wrong_payload_type_rejected():
    env = hosted()
    env["payloadType"] = "text/plain"
    assert not sp.verify(env, ART, POLICY).ok


def test_multiple_trusted_builders():
    k2 = b"FAKE-second-key"
    pol = sp.Policy([sp.TrustedBuilder(BUILDER, KEY), sp.TrustedBuilder("https://example.invalid/b2", k2)],
                    "https://github.com/example/app")
    env = sp.HostedBuilder("https://example.invalid/b2", k2).build_and_sign(**COMMON)
    assert sp.verify(env, ART, pol).ok


def test_empty_allowlist_rejects_everything():
    pol = sp.Policy([], "https://github.com/example/app")
    assert not sp.verify(hosted(), ART, pol).ok


def test_pae_is_length_prefixed():
    assert sp.pae("a/b", b"xyz") == b"DSSEv1 3 a/b 3 xyz"
