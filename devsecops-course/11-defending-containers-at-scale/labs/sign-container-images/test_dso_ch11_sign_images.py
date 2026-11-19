from aisec_lab import load_lab_module

sv = load_lab_module(__file__, "sign_verify")
KEY = b"test-key"


def _reg():
    m = {"layers": ["a"]}
    d = sv.digest_of(m)
    return {"tags": {"app:1": d}, "manifests": {d: m}, "sigs": {d: [sv.sign(d, "ci", KEY)]}}, d, m


def test_valid_signature_verifies():
    reg, _, _ = _reg()
    assert sv.verify(reg, "app:1", {"ci": KEY}, {"ci"})[0]


def test_repointed_tag_has_no_signature():
    reg, _, _ = _reg()
    m2 = {"layers": ["a", "evil"]}
    d2 = sv.digest_of(m2)
    reg["manifests"][d2] = m2
    reg["tags"]["app:1"] = d2
    ok, why = sv.verify(reg, "app:1", {"ci": KEY}, {"ci"})
    assert not ok and "no valid signature" in why


def test_tampered_manifest_detected():
    reg, d, _ = _reg()
    reg["manifests"][d] = {"layers": ["a", "evil"]}
    assert "tampered" in sv.verify(reg, "app:1", {"ci": KEY}, {"ci"})[1]


def test_wrong_key_or_disallowed_signer_rejected():
    reg, _, _ = _reg()
    assert not sv.verify(reg, "app:1", {"ci": b"other"}, {"ci"})[0]
    assert not sv.verify(reg, "app:1", {"ci": KEY}, {"someone"})[0]


def test_unknown_reference():
    reg, _, _ = _reg()
    assert sv.verify(reg, "nope:1", {"ci": KEY}, {"ci"}) == (False, "unknown reference")
