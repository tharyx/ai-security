"""Model-file tests: loading a pickle runs code; scanning it does not; the secure loader refuses it.

The only pickle that is ever LOADED here is built from harmless_payload.py: its "payload"
writes a canary file. The malicious-style bytes in attacks.py are only scanned.

Run from the repository root:
    python -m pytest 06-ai-devsecops/docker -v
"""

import collections
import io
import pickle
import tempfile
import zipfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

ps = load_lab_module(__file__, "pickle_scan")
payload = load_lab_module(__file__, "harmless_payload")
attacks = load_lab_module(__file__, "attacks")
vulnerable_loader = load_lab_module(__file__, "vulnerable_loader")


@pytest.fixture
def tmp_dir():
    """A fresh temporary folder (plain tempfile, so it works in locked-down environments too)."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def trap(tmp_dir):
    """A booby-trapped .pkl file and the canary path its payload would create."""
    canary = tmp_dir / "payload-ran.txt"
    model = tmp_dir / "model.pkl"
    model.write_bytes(pickle.dumps(payload.BoobyTrappedModel(str(canary))))
    return model, canary


# ---------- Part 1: prove the risk is real ----------------------------------------

def test_loading_a_pickle_runs_code(trap):
    model, canary = trap
    vulnerable_loader.load_model(model)
    assert canary.read_text() == payload.CANARY_TEXT  # code ran just by LOADING the "model"


# ---------- Part 2: the scanner sees it without running it -----------------------------

def test_scanning_never_executes_the_payload(trap):
    model, canary = trap
    result = ps.scan_file(model)
    assert not canary.exists()
    assert result.verdict == "UNSAFE" and result.calls >= 1
    assert any(g.endswith(".leave_canary") for g in result.unknown)


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_scanner_resolves_globals_in_every_protocol(tmp_dir, protocol):
    data = pickle.dumps(payload.BoobyTrappedModel(str(tmp_dir / "x")), protocol=protocol)
    result = ps.scan_pickle_bytes(data)
    assert any(g.endswith(".leave_canary") for g in result.globals)  # GLOBAL (old) or STACK_GLOBAL (new)
    assert result.verdict != "SAFE"


@pytest.mark.parametrize("name", list(attacks.MALICIOUS_STYLE))
def test_every_malicious_style_sample_is_blocked(name):
    assert ps.scan_pickle_bytes(attacks.MALICIOUS_STYLE[name], name).verdict != "SAFE"


@pytest.mark.parametrize("name", ["global_os_system", "stack_global_os_system", "memo_trick_os_system",
                                  "broken_stream_after_payload", "second_pickle_appended"])
def test_os_system_is_found_despite_evasion(name):
    result = ps.scan_pickle_bytes(attacks.MALICIOUS_STYLE[name], name)
    assert result.verdict == "DANGEROUS"
    assert "os.system" in result.dangerous


def test_allowlist_catches_what_the_denylist_misses():
    result = ps.scan_pickle_bytes(attacks.MALICIOUS_STYLE["gadget_not_on_denylist"])
    assert result.dangerous == []          # denylist: "looks fine"
    assert result.unknown == ["timeit.timeit"]
    assert result.verdict == "UNSAFE"      # allowlist: "not approved, refuse"


def test_torch_style_zip_archive_is_scanned_inside(tmp_dir):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", attacks.MALICIOUS_STYLE["stack_global_os_system"])
        zf.writestr("archive/version", "3\n")
    (tmp_dir / "model.pt").write_bytes(buf.getvalue())
    result = ps.scan_file(tmp_dir / "model.pt")
    assert result.format == "zip(pickle)" and result.verdict == "DANGEROUS"


def test_benign_state_dict_is_safe():
    data = pickle.dumps(collections.OrderedDict(w=[0.1, 0.2], b=b"\x00\x01"), protocol=2)
    assert ps.scan_pickle_bytes(data).verdict == "SAFE"


# ---------- Part 3: safetensors is data, not code --------------------------------------

def test_safetensors_round_trip_is_safe(tmp_dir):
    path = tmp_dir / "model.safetensors"
    ps.write_safetensors(path, {"layer0.weight": [0.5, -1.0, 2.0]}, metadata={"format": "pt"})
    assert ps.scan_file(path).verdict == "SAFE"
    header = ps.safe_load_model(path)
    assert header["layer0.weight"]["shape"] == [3]


def test_corrupt_safetensors_is_rejected(tmp_dir):
    path = tmp_dir / "model.safetensors"
    ps.write_safetensors(path, {"w": [1.0, 2.0]})
    path.write_bytes(path.read_bytes()[:-4])  # truncate the tensor data
    assert ps.scan_file(path).verdict == "UNSAFE"
    with pytest.raises(ValueError):
        ps.safe_load_model(path)


# ---------- Part 4: secure loader, layer by layer ----------------------------------------

def test_secure_loader_refuses_pickle_formats_by_default(trap):
    model, canary = trap
    with pytest.raises(ps.UnsafeModelError, match="safetensors"):
        ps.safe_load_model(model)
    assert not canary.exists()


def test_scan_layer_alone_blocks_the_payload(trap):
    model, canary = trap
    with pytest.raises(ps.UnsafeModelError, match="UNSAFE"):
        ps.safe_load_model(model, prefer_safetensors=False, restricted=False)
    assert not canary.exists()


def test_restricted_unpickler_alone_blocks_the_payload(trap):
    """Assume the scanner was fooled or skipped. Load-time allowlisting still holds."""
    model, canary = trap
    with pytest.raises(pickle.UnpicklingError, match="not allowed"):
        ps.safe_load_model(model, prefer_safetensors=False, scan=False)
    assert not canary.exists()


def test_with_every_layer_off_the_payload_runs(trap):
    model, canary = trap
    ps.safe_load_model(model, prefer_safetensors=False, scan=False, restricted=False)
    assert canary.exists()  # this is why the layers exist


def test_benign_pickle_still_loads_when_pickle_is_allowed(tmp_dir):
    path = tmp_dir / "state.pkl"
    path.write_bytes(pickle.dumps(collections.OrderedDict(w=[0.1, 0.2])))
    loaded = ps.safe_load_model(path, prefer_safetensors=False)
    assert loaded == collections.OrderedDict(w=[0.1, 0.2])
