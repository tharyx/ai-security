"""Spawn the server as a real subprocess (python -I) and talk JSON-RPC over stdin/stdout."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"
CONFIG = HERE / "config.json"


def run_session(messages: list, config: Path = CONFIG) -> list:
    """Send messages, close stdin, return every reply the server printed."""
    payload = "".join((m if isinstance(m, str) else json.dumps(m)) + "\n" for m in messages)
    proc = subprocess.run([sys.executable, "-I", str(SERVER), "--config", str(config)],
                          input=payload, capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def rpc(i: int, method: str, params: dict | None = None) -> dict:
    msg = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


INIT = rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "test", "version": "0"}})
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}


def test_initialize_and_tools_list_over_stdio():
    replies = run_session([INIT, INITIALIZED, rpc(2, "tools/list")])
    assert len(replies) == 2  # the notification got no reply
    init = replies[0]["result"]
    assert init["protocolVersion"] == "2025-06-18"
    assert init["serverInfo"]["name"] == "lab-files-server"
    assert "tools" in init["capabilities"]
    names = [t["name"] for t in replies[1]["result"]["tools"]]
    assert names == ["echo", "add", "list_files", "read_file"]


def test_unsupported_protocol_version_gets_servers_latest():
    bad = rpc(1, "initialize", {"protocolVersion": "1999-01-01", "capabilities": {}})
    assert run_session([bad])[0]["result"]["protocolVersion"] == "2025-11-25"


def test_config_controls_which_tools_exist():
    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / "c.json"
        cfg.write_text(json.dumps({"name": "tiny", "tools_enabled": ["echo"], "root_dir": "."}))
        replies = run_session([INIT, rpc(2, "tools/list"),
                               rpc(3, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}})], cfg)
    assert [t["name"] for t in replies[1]["result"]["tools"]] == ["echo"]
    assert replies[2]["error"]["code"] == -32602  # a disabled tool is unknown


def test_tool_calls_work():
    replies = run_session([INIT,
                           rpc(2, "tools/call", {"name": "add", "arguments": {"a": 2, "b": 40}}),
                           rpc(3, "tools/call", {"name": "read_file", "arguments": {"path": "hello.txt"}})])
    assert replies[1]["result"]["content"][0]["text"] == "42"
    assert "Hello from the sandbox" in replies[2]["result"]["content"][0]["text"]


def test_root_dir_is_enforced():
    attempts = ["../secret-outside-root.txt", "sub/../../secret-outside-root.txt",
                str(HERE / "secret-outside-root.txt"), "..\\secret-outside-root.txt"]
    msgs = [INIT] + [rpc(10 + i, "tools/call", {"name": "read_file", "arguments": {"path": p}})
                     for i, p in enumerate(attempts)]
    for reply in run_session(msgs)[1:]:
        result = reply["result"]
        assert result["isError"] is True
        assert "CANARY" not in json.dumps(result)


def test_calls_before_initialize_are_rejected():
    assert run_session([rpc(1, "tools/list")])[0]["error"]["code"] == -32600


def test_bad_input_does_not_crash_the_server():
    replies = run_session(["{not json", json.dumps([1, 2]), INIT, rpc(2, "nope/nothing"),
                           rpc(3, "tools/call", {"name": "add", "arguments": {"a": "x", "b": 1}}),
                           rpc(4, "tools/call", {"name": "echo", "arguments": {"text": "ok", "extra": 1}}),
                           rpc(5, "ping")])
    assert replies[0]["error"]["code"] == -32700
    assert replies[1]["error"]["code"] == -32600
    assert replies[3]["error"]["code"] == -32601
    assert replies[4]["result"]["isError"] is True
    assert replies[5]["result"]["isError"] is True
    assert replies[6]["result"] == {}


def test_stdout_contains_only_json_lines():
    proc = subprocess.run([sys.executable, "-I", str(SERVER), "--config", str(CONFIG)],
                          input=json.dumps(INIT) + "\n", capture_output=True, text=True, timeout=20)
    for line in proc.stdout.splitlines():
        json.loads(line)  # a stray print() would break this
    assert "started" in proc.stderr  # logs go to stderr
