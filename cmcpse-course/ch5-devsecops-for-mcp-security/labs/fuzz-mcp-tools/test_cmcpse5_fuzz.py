"""Fuzz lab tests: the fuzzer finds the planted bugs, and the fixed server survives the same campaign.

Run from the repository root:
    python -m pytest cmcpse-course/ch5-devsecops-for-mcp-security/labs/fuzz-mcp-tools -v
"""

import os
import random
import subprocess
import urllib.request
from pathlib import Path

from aisec_lab import load_lab_module

fz = load_lab_module(__file__, "fuzzer")
SERVERS = Path(__file__).resolve().parent.parent / "sast-vulnerable-mcp-server"
VULN, FIXED = SERVERS / "vulnerable_server", SERVERS / "fixed_server"


def kinds(findings):
    return {f.kind for f in findings}


def test_fuzzer_finds_all_five_bug_classes_in_vulnerable_server():
    findings = fz.fuzz(VULN, iterations=300, seed=1234)
    assert kinds(findings) == {"crash", "path-traversal", "command-injection", "ssrf", "info-leak"}


def test_each_finding_names_the_responsible_tool():
    by_kind = {}
    for f in fz.fuzz(VULN, iterations=300, seed=1234):
        by_kind.setdefault(f.kind, set()).add(f.tool)
    assert by_kind["path-traversal"] == {"read_note"}
    assert by_kind["ssrf"] == {"fetch_url"}
    assert by_kind["command-injection"] == {"ping_host", "archive_logs"}
    assert {"apply_discount", "split_bill"} <= by_kind["crash"]


def test_fixed_server_has_zero_findings():
    findings = fz.fuzz(FIXED, iterations=500, seed=1234)
    assert findings == [], [str(f) for f in findings]


def test_fixed_server_survives_other_seeds():
    for seed in (1, 99, 31337):
        assert fz.fuzz(FIXED, iterations=300, seed=seed) == []


def test_same_seed_gives_same_findings():
    a = [(f.kind, f.tool) for f in fz.fuzz(VULN, iterations=200, seed=5)]
    b = [(f.kind, f.tool) for f in fz.fuzz(VULN, iterations=200, seed=5)]
    assert a == b


def test_sandbox_records_and_never_runs_anything_real():
    real_run, real_open = subprocess.run, urllib.request.urlopen
    with fz.sandbox() as fx:
        subprocess.run("echo should-not-run; touch /tmp/never", shell=True)
        os.system("echo nope")
        urllib.request.urlopen("http://169.254.169.254/")
    assert len(fx.shell_calls) == 2 and fx.urls == ["http://169.254.169.254/"]
    assert subprocess.run is real_run and urllib.request.urlopen is real_open


def test_valid_requests_do_not_trigger_oracles():
    ws = fz.Workspace()
    try:
        server, config = fz.load_package(FIXED, "valid_check")
        config.NOTES_DIR = str(ws.notes)
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_note", "arguments": {"name": "hello.txt"}}}
        with fz.sandbox() as fx:
            response = server.handle(req)
        assert response["result"]["content"][0]["text"] == "hello from notes"
        assert fz._check("read_note", {"name": "hello.txt"}, response, fx, ws) == []
        req["params"] = {"name": "fetch_url", "arguments": {"url": "https://example.com/"}}
        with fz.sandbox() as fx:
            response = server.handle(req)
        assert fx.urls == ["https://example.com/"]
        assert fz._check("fetch_url", {"url": "https://example.com/"}, response, fx, ws) == []
    finally:
        ws.close()


def test_generators_produce_variety_and_bad_types():
    ws = fz.Workspace()
    try:
        rng = random.Random(1)
        schema = {"type": "object", "properties": {"name": {"type": "string"}, "n": {"type": "integer"}}, "required": ["name", "n"]}
        samples = [fz.generate_arguments(rng, schema, ws) for _ in range(300)]
        assert any(not isinstance(s, dict) for s in samples)          # arguments of the wrong shape
        assert any(isinstance(s, dict) and "extra" in s for s in samples)
        assert any(isinstance(s, dict) and len(s) < 2 for s in samples)  # missing argument
        assert any(isinstance(s, dict) and isinstance(s.get("name"), str) and "../" in s["name"] for s in samples)
    finally:
        ws.close()


def test_traversal_finding_proves_the_canary_escaped():
    f = next(x for x in fz.fuzz(VULN, iterations=50, seed=3) if x.kind == "path-traversal")
    assert "canary" in f.detail
