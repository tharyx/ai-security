"""Tests for model_sign.py. Models are tiny fake files in a temporary directory."""

from __future__ import annotations

import tempfile
from contextlib import contextmanager
from pathlib import Path

from aisec_lab import load_lab_module

ms = load_lab_module(__file__, "model_sign")
KEY = b"lab-only-secret-key"
SIGNER = "ci@release.example"


@contextmanager
def signed_model():
    with tempfile.TemporaryDirectory() as tmp:
        model = Path(tmp) / "model"
        (model / "sub").mkdir(parents=True)
        (model / "model.safetensors").write_bytes(b"\x00weights" * 100)
        (model / "config.json").write_text('{"layers": 2}', encoding="utf-8")
        (model / "sub" / "tokenizer.json").write_text('{"vocab": []}', encoding="utf-8")
        manifest = ms.build_manifest(model, "tiny", "1.0", SIGNER)
        yield model, ms.sign_manifest(manifest, KEY)


def test_untouched_model_verifies():
    with signed_model() as (model, bundle):
        res = ms.verify_model(model, bundle, KEY, expected_signer=SIGNER)
        assert res.ok and res.problems == []


def test_manifest_lists_every_file_with_sha256():
    with signed_model() as (model, bundle):
        files = bundle["manifest"]["files"]
        assert set(files) == {"model.safetensors", "config.json", "sub/tokenizer.json"}
        assert all(len(h) == 64 for h in files.values())


def test_modified_weights_are_detected():
    with signed_model() as (model, bundle):
        w = model / "model.safetensors"
        data = bytearray(w.read_bytes())
        data[5] ^= 0x01                                   # flip one bit
        w.write_bytes(bytes(data))
        res = ms.verify_model(model, bundle, KEY)
        assert not res.ok and res.problems == ["modified file: model.safetensors"]


def test_added_and_removed_files_are_detected():
    with signed_model() as (model, bundle):
        (model / "backdoor.py").write_text("print('hi')", encoding="utf-8")
        (model / "config.json").unlink()
        res = ms.verify_model(model, bundle, KEY)
        assert "unexpected extra file: backdoor.py" in res.problems
        assert "missing file: config.json" in res.problems


def test_editing_the_manifest_breaks_the_signature():
    with signed_model() as (model, bundle):
        # attacker edits the file AND updates the hash in the manifest to match
        (model / "config.json").write_text('{"layers": 99}', encoding="utf-8")
        bundle["manifest"]["files"]["config.json"] = ms.sha256_file(model / "config.json")
        res = ms.verify_model(model, bundle, KEY)
        assert not res.ok and "signature invalid" in res.problems[0]


def test_wrong_key_fails():
    with signed_model() as (model, bundle):
        assert not ms.verify_model(model, bundle, b"another-key").ok


def test_signer_identity_is_checked():
    with signed_model() as (model, bundle):
        res = ms.verify_model(model, bundle, KEY, expected_signer="someone-else@example.com")
        assert not res.ok and "unexpected signer" in res.problems[0]


def test_bundle_round_trips_through_a_file():
    with signed_model() as (model, bundle):
        path = model.parent / "model.sig.json"
        ms.save_bundle(bundle, path)
        assert ms.verify_model(model, ms.load_bundle(path), KEY).ok


def test_manifest_is_canonical_and_deterministic():
    with signed_model() as (model, bundle):
        again = ms.build_manifest(model, "tiny", "1.0", SIGNER)
        assert ms.canonical(again) == ms.canonical(bundle["manifest"])
        assert ms.sign_manifest(again, KEY)["signature"] == bundle["signature"]


def test_missing_signature_is_rejected():
    with signed_model() as (model, bundle):
        bundle.pop("signature")
        assert not ms.verify_model(model, bundle, KEY).ok
