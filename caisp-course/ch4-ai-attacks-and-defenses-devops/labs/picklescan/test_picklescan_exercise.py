"""Picklescan exercise: scan a folder of model files WITHOUT loading them.

Run from the repository root:
    python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops/labs/picklescan -v
"""

import pickle
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

ps = load_lab_module(__file__, "mini_picklescan")
samples = load_lab_module(__file__, "samples")


@pytest.fixture(scope="module")
def folder():
    with tempfile.TemporaryDirectory() as d:
        expected = samples.build(d)
        yield Path(d), expected


def test_every_sample_gets_its_expected_verdict(folder):
    d, expected = folder
    got = {r.source.split("\\")[-1].split("/")[-1]: r.verdict for r in ps.scan_folder(d)}
    assert got == expected


def test_the_memo_trick_is_still_caught(folder):
    d, _ = folder
    assert "os.system" in ps.scan_file(d / "evil_memo_trick.pkl").imports


def test_a_payload_followed_by_a_broken_stream_is_not_called_safe(folder):
    d, _ = folder
    assert ps.scan_file(d / "evil_broken_stream.pkl").verdict == "DANGEROUS"


def test_a_pickle_hidden_inside_a_pt_archive_is_found(folder):
    d, _ = folder
    assert ps.scan_file(d / "evil_inside_model.pt").imports == ["os.system"]


def test_an_unknown_gadget_is_flagged_by_the_allowlist_even_without_a_denylist_entry(folder):
    d, _ = folder
    r = ps.scan_file(d / "unknown_gadget.pkl")
    assert r.imports == ["timeit.timeit"] and r.verdict == "SUSPICIOUS"


def test_scanning_never_runs_the_payload(folder):
    d, _ = folder
    ps.scan_folder(d)
    assert not list(d.glob("CANARY*"))  # `echo CANARY` would not create a file, so also check no new files appeared
    assert sorted(p.name for p in d.iterdir()) == sorted(samples.build(d))


def test_garbage_bytes_are_unparseable_not_safe():
    assert ps.scan_pickle_bytes(b"\xff\xfe not a pickle").verdict == "UNPARSEABLE"


def test_plain_data_pickle_is_safe():
    assert ps.scan_pickle_bytes(pickle.dumps({"a": [1, 2, 3]})).verdict == "SAFE"


def test_main_exit_code_reflects_the_worst_file(folder, capsys):
    d, _ = folder
    assert ps.main([str(d)]) == 1
    out = capsys.readouterr().out
    assert "DANGEROUS" in out and "SAFE" in out
