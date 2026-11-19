"""Tests for model_scan.py. Every file lives in a temporary directory."""

from __future__ import annotations

import pickle
import struct
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

ms = load_lab_module(__file__, "model_scan")


def test_clean_pickle_scans_safe_and_loads():
    data = ms.make_clean_pickle()
    res = ms.scan_pickle_bytes(data)
    assert res.verdict == "SAFE" and res.globals == []
    assert ms.restricted_loads(data) == ms.make_state_dict()


def test_naive_load_runs_the_payload_and_writes_the_canary():
    with tempfile.TemporaryDirectory() as tmp:
        canary = Path(tmp) / "canary.txt"
        model = Path(tmp) / "model.pkl"
        model.write_bytes(ms.make_booby_trapped_pickle(str(canary)))
        assert not canary.exists()
        ms.naive_load(str(model))                      # the vulnerability: loading IS executing
        assert canary.read_text() == ms.CANARY_TEXT


def test_scanner_flags_the_booby_trapped_pickle_without_running_it():
    with tempfile.TemporaryDirectory() as tmp:
        canary = Path(tmp) / "canary.txt"
        data = ms.make_booby_trapped_pickle(str(canary))
        res = ms.scan_pickle_bytes(data)
        assert res.verdict == "UNSAFE"
        assert any(g.endswith(".leave_canary") for g in res.globals)
        assert res.calls >= 1
        assert not canary.exists(), "scanning must not execute the payload"


def test_known_dangerous_reference_is_flagged_dangerous_and_never_loaded():
    res = ms.scan_pickle_bytes(ms.NEVER_LOAD_OS_SYSTEM_PICKLE)
    assert res.verdict == "DANGEROUS"
    assert res.globals == ["os.system"]


def test_dangerous_helper():
    assert ms.is_dangerous("os.system") and ms.is_dangerous("subprocess.Popen")
    assert ms.is_dangerous("builtins.eval") and not ms.is_dangerous("builtins.set")
    assert not ms.is_dangerous("collections.OrderedDict")


def test_malformed_stream_is_not_called_safe():
    assert ms.scan_pickle_bytes(b"\x80\x04\x95garbage").verdict == "UNSAFE"


def test_safe_loader_refuses_the_trapped_model_and_no_canary_appears():
    with tempfile.TemporaryDirectory() as tmp:
        canary = Path(tmp) / "canary.txt"
        model = Path(tmp) / "model.pkl"
        model.write_bytes(ms.make_booby_trapped_pickle(str(canary)))
        with pytest.raises(ms.RefusedModel):
            ms.safe_load_model(str(model))
        assert not canary.exists()


def test_restricted_unpickler_holds_even_when_the_scanner_is_switched_off():
    with tempfile.TemporaryDirectory() as tmp:
        canary = Path(tmp) / "canary.txt"
        model = Path(tmp) / "model.pkl"
        model.write_bytes(ms.make_booby_trapped_pickle(str(canary)))
        with pytest.raises(pickle.UnpicklingError):
            ms.safe_load_model(str(model), scan=False)
        assert not canary.exists()


def test_benign_path_clean_pickle_loads_through_the_safe_loader():
    with tempfile.TemporaryDirectory() as tmp:
        model = Path(tmp) / "model.pkl"
        model.write_bytes(ms.make_clean_pickle())
        assert ms.safe_load_model(str(model)) == ms.make_state_dict()


def test_safetensors_round_trip():
    tensors = {"a": [1.0, 2.0, 3.0], "b": [0.5]}
    blob = ms.safetensors_dump(tensors, {"format": "pt"})
    assert ms.safetensors_load(blob) == tensors


def test_safetensors_file_cannot_carry_the_payload():
    with tempfile.TemporaryDirectory() as tmp:
        canary = Path(tmp) / "canary.txt"
        evil_pickle = ms.make_booby_trapped_pickle(str(canary))
        path = Path(tmp) / "model.safetensors"
        path.write_bytes(evil_pickle)                  # a pickle wearing a .safetensors name
        with pytest.raises(ValueError):
            ms.safe_load_model(str(path))
        assert not canary.exists()


def test_safetensors_parser_rejects_bad_offsets_and_dtypes():
    blob = ms.safetensors_dump({"a": [1.0, 2.0]})
    (hlen,) = struct.unpack("<Q", blob[:8])
    bad_header = blob[8:8 + hlen].replace(b'"data_offsets":[0,8]', b'"data_offsets":[0,800]')
    forged = struct.pack("<Q", len(bad_header)) + bad_header + blob[8 + hlen:]
    with pytest.raises(ValueError):
        ms.safetensors_load(forged)
    with pytest.raises(ValueError):
        ms.safetensors_load(blob.replace(b'"F32"', b'"I64"'))
    with pytest.raises(ValueError):
        ms.safetensors_load(b"tiny")


def test_safe_loader_loads_safetensors():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "model.safetensors"
        path.write_bytes(ms.safetensors_dump({"w": [1.0, 2.0]}))
        assert ms.safe_load_model(str(path)) == {"w": [1.0, 2.0]}
