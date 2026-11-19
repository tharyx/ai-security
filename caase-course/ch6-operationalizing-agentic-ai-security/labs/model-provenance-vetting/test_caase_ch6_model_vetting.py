import copy
import tempfile
from pathlib import Path

from aisec_lab import load_lab_module

v = load_lab_module(__file__, "model_vetting")
H = "d" * 64
CARD = {
    "name": "tiny-instruct-4b",
    "source_org": "example-lab",
    "license": "apache-2.0",
    "files": {"model.safetensors": H, "tokenizer.json": "e" * 64},
    "model_card_present": True,
    "training_data_disclosed": True,
    "evals": {"injection_resistance": 0.81, "harmful_refusal": 0.92},
}
OBS = {"model.safetensors": H, "tokenizer.json": "e" * 64}


def card(**kw):
    c = copy.deepcopy(CARD)
    c.update(kw)
    return c


def test_good_model_routes_to_production():
    d = v.vet(CARD, OBS)
    assert d.route == "production"


def test_hash_mismatch_rejected():
    d = v.vet(CARD, {**OBS, "model.safetensors": "0" * 64})
    assert d.rejected and "hash mismatch" in d.reasons[0]


def test_extra_unlisted_file_rejected():
    assert v.vet(CARD, {**OBS, "extra_code.py": "1" * 64}).rejected


def test_pickle_format_rejected_even_if_hash_matches():
    c = card(files={"pytorch_model.bin": H})
    d = v.vet(c, {"pytorch_model.bin": H})
    assert d.rejected and any("pickle" in r for r in d.reasons)


def test_unknown_org_is_sandbox_only():
    assert v.vet(card(source_org="random-uploader"), OBS).route == "sandbox"


def test_typosquat_org_rejected():
    d = v.vet(card(source_org="examp1e-lab"), OBS)
    assert d.rejected and any("typosquat" in r for r in d.reasons)


def test_licence_handling():
    assert v.vet(card(license="cc-by-nc-4.0"), OBS).rejected
    assert v.vet(card(license="llama-community"), OBS).route == "sandbox"
    assert v.vet(card(license=""), OBS).rejected


def test_missing_or_weak_evals_sandbox():
    assert v.vet(card(evals={}), OBS).route == "sandbox"
    weak = v.vet(card(evals={"injection_resistance": 0.2, "harmful_refusal": 0.9}), OBS)
    assert weak.route == "sandbox" and any("below minimum" in r for r in weak.reasons)


def test_trust_remote_code_is_sandbox():
    assert v.vet(card(requires_trust_remote_code=True), OBS).route == "sandbox"


def test_no_declared_hashes_cannot_be_production():
    assert v.vet(card(files={}), {}).route == "sandbox"


def test_sha256_file_matches_hashlib():
    import hashlib

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "w.safetensors"
        p.write_bytes(b"FAKE-WEIGHTS" * 1000)
        assert v.sha256_file(p) == hashlib.sha256(p.read_bytes()).hexdigest()
