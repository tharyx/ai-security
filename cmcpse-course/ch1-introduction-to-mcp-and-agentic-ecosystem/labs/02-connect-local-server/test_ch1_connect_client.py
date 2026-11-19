"""The client talks to the lab 01 server over a real stdio subprocess."""

import json
import sys
import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

c = load_lab_module(__file__, "client")
HERE = Path(__file__).resolve().parent
SERVER = HERE.parent / "01-install-configure-server" / "server.py"
CONFIG = HERE.parent / "01-install-configure-server" / "config.json"


def cmd(config: Path = CONFIG) -> list[str]:
    return [sys.executable, "-I", str(SERVER), "--config", str(config)]


def test_handshake_negotiates_version_and_capabilities():
    with c.MCPClient(cmd()) as client:
        client.initialize()
        assert client.protocol_version == c.CLIENT_VERSION
        assert client.server_info["name"] == "lab-files-server"
        assert client.has_capability("tools")
        assert not client.has_capability("resources")


def test_list_and_call_tools():
    with c.MCPClient(cmd()) as client:
        client.initialize()
        assert {t["name"] for t in client.list_tools()} == {"echo", "add", "list_files", "read_file"}
        assert c.result_text(client.call_tool("add", {"a": 1.5, "b": 2})) == "3.5"
        assert "hello.txt" in c.result_text(client.call_tool("list_files"))


def test_protocol_error_raises_and_tool_error_is_data():
    with c.MCPClient(cmd()) as client:
        client.initialize()
        with pytest.raises(c.MCPError) as exc:
            client.call_tool("nope")
        assert exc.value.code == -32602
        bad = client.call_tool("read_file", {"path": "../secret-outside-root.txt"})
        assert bad["isError"] is True


def test_calling_before_initialize_is_refused_by_the_server():
    with c.MCPClient(cmd()) as client:
        with pytest.raises(c.MCPError) as exc:
            client.request("tools/list")
        assert exc.value.code == -32600


def test_client_refuses_features_the_server_did_not_advertise():
    with c.MCPClient(cmd()) as client:
        client.initialize()
        client.server_capabilities = {}  # pretend the server had no tools
        with pytest.raises(RuntimeError):
            client.list_tools()


def test_version_mismatch_disconnects():
    old = c.CLIENT_VERSION
    c.CLIENT_VERSION = "1999-01-01"  # the server will answer with its own latest version
    try:
        with c.MCPClient(cmd()) as client:
            with pytest.raises(ConnectionError):
                client.initialize()
    finally:
        c.CLIENT_VERSION = old


def test_dead_server_is_reported():
    with tempfile.TemporaryDirectory() as d:
        bad_cfg = Path(d) / "bad.json"
        bad_cfg.write_text(json.dumps({"tools_enabled": ["not_a_tool"]}))
        with c.MCPClient(cmd(bad_cfg), timeout=5) as client:
            with pytest.raises(ConnectionError):
                client.initialize()
