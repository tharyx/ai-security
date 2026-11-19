"""Optional: the same idea with Hypothesis (pip install hypothesis). NOT executed by the repo author.

Hypothesis generates and SHRINKS inputs for you: a failing 10,000 character string becomes the
shortest string that still fails. Run with:  pytest hypothesis_variant.py
(The file is not named test_*.py, so the normal course test run skips it.)
"""

import importlib.util
import sys
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fuzzer", HERE / "fuzzer.py")
fuzzer = importlib.util.module_from_spec(spec)
sys.modules["fuzzer"] = fuzzer
spec.loader.exec_module(fuzzer)

WS = fuzzer.Workspace()
SERVER, CONFIG = fuzzer.load_package(HERE.parent / "sast-vulnerable-mcp-server" / "vulnerable_server", "hyp")
CONFIG.NOTES_DIR = str(WS.notes)


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.text(), st.sampled_from(["../secret.txt", str(WS.secret)])))
def test_read_note_never_returns_the_canary(name):
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_note", "arguments": {"name": name}}}
    with fuzzer.sandbox():
        try:
            response = SERVER.handle(request)
        except Exception:
            return  # a crash is a different bug; this test is about the canary
    assert WS.canary not in repr(response)
