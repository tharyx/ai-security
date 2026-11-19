"""Tests for the image signing twin."""

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "image_signing")
REF = "registry.example/shop/api:1.0"


def fresh():
    reg = s.Registry()
    reg.push(REF, b"v1")
    return reg


def test_sign_and_verify():
    reg = fresh()
    s.sign(reg, REF)
    assert s.verify(reg, REF)[0]


def test_unsigned_image_fails():
    assert not s.verify(fresh(), REF)[0]


def test_wrong_key_fails():
    reg = fresh()
    s.sign(reg, REF)
    assert not s.verify(reg, REF, key=b"attacker-key")[0]


def test_tag_repointed_after_signing_fails_verification():
    reg = fresh()
    s.sign(reg, REF)
    reg.push(REF, b"EVIL")
    assert not s.verify(reg, REF)[0]


def test_signature_cannot_be_replayed_onto_another_digest():
    reg = fresh()
    sig = s.sign(reg, REF)
    d2 = reg.push("registry.example/shop/api:2.0", b"v2")
    reg.signatures[d2] = [sig]  # attacker copies the signature to another image
    assert not s.verify(reg, "registry.example/shop/api:2.0")[0]


def test_signature_for_other_repository_rejected():
    reg = fresh()
    sig = s.sign(reg, REF)
    d = reg.push("registry.example/other/app:1.0", b"v1")  # same content, same digest, different repo
    reg.signatures[d] = [sig]
    assert not s.verify(reg, "registry.example/other/app:1.0")[0]


def test_required_claims():
    reg = fresh()
    s.sign(reg, REF, claims={"pipeline": "release"})
    assert s.verify(reg, REF, required_claims={"pipeline": "release"})[0]
    assert not s.verify(reg, REF, required_claims={"pipeline": "dev"})[0]


def test_tampered_payload_rejected():
    reg = fresh()
    sig = s.sign(reg, REF)
    sig["payload"] = sig["payload"].replace("shop/api", "shop/apx")
    assert not s.verify(reg, REF)[0]


def test_attestation_roundtrip_and_wrong_type():
    reg = fresh()
    s.attest(reg, REF, "https://slsa.dev/provenance/v1", {"builder": "ci.example"})
    assert s.verify_attestation(reg, REF, "https://slsa.dev/provenance/v1") == {"builder": "ci.example"}
    assert s.verify_attestation(reg, REF, "https://cyclonedx.org/bom") is None


def test_attestation_does_not_follow_a_moved_tag():
    reg = fresh()
    s.attest(reg, REF, "https://slsa.dev/provenance/v1", {"builder": "ci.example"})
    reg.push(REF, b"EVIL")
    assert s.verify_attestation(reg, REF, "https://slsa.dev/provenance/v1") is None


def test_identity_pinning():
    cert = {"san": "https://ci.example/wf@main", "issuer": "https://oidc.ci.example"}
    assert s.verify_identity(cert, "https://ci.example/wf@main", "https://oidc.ci.example")
    assert not s.verify_identity(cert, "https://ci.example/wf@dev", "https://oidc.ci.example")
