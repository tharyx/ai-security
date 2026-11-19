"""Tools, resources, prompt and validation of the notes server, over a real stdio subprocess."""

import json
import subprocess
import sys
from pathlib import Path

from aisec_lab import load_lab_module

mod = load_lab_module(__file__, "notes_server")
SERVER = Path(__file__).resolve().parent / "notes_server.py"


def rpc(i, method, params=None):
    msg = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def session(*calls) -> list:
    """calls are (method, params). initialize is added first. Returns replies after initialize."""
    msgs = [rpc(0, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})]
    msgs += [rpc(i + 1, m, p) for i, (m, p) in enumerate(calls)]
    proc = subprocess.run([sys.executable, "-I", str(SERVER)], input="".join(json.dumps(m) + "\n" for m in msgs),
                          capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    return [json.loads(x) for x in proc.stdout.splitlines()][1:]


def test_capabilities_announce_all_three_primitives():
    proc = subprocess.run([sys.executable, "-I", str(SERVER)], capture_output=True, text=True, timeout=20,
                          input=json.dumps(rpc(0, "initialize", {"protocolVersion": "2025-06-18"})) + "\n")
    caps = json.loads(proc.stdout)["result"]["capabilities"]
    assert set(caps) == {"tools", "resources", "prompts"}


def test_two_tools_and_two_resources_and_one_prompt():
    tools, res, prompts = session(("tools/list", None), ("resources/list", None), ("prompts/list", None))
    assert [t["name"] for t in tools["result"]["tools"]] == ["add_note", "search_notes"]
    assert [r["uri"] for r in res["result"]["resources"]] == ["notes://all", "docs://about"]
    assert [p["name"] for p in prompts["result"]["prompts"]] == ["summarize_notes"]


def test_add_note_changes_what_the_resource_returns():
    add, read = session(("tools/call", {"name": "add_note", "arguments": {"title": "Plan", "text": "learn MCP"}}),
                        ("resources/read", {"uri": "notes://all"}))
    assert add["result"]["isError"] is False
    # each subprocess has fresh state, but one session keeps its state between calls:
    notes = json.loads(read["result"]["contents"][0]["text"])
    assert [n["title"] for n in notes] == ["Welcome", "Plan"]


def test_search_notes():
    hit, miss = session(("tools/call", {"name": "search_notes", "arguments": {"query": "FIRST"}}),
                        ("tools/call", {"name": "search_notes", "arguments": {"query": "zzz"}}))
    assert "Welcome" in hit["result"]["content"][0]["text"]
    assert miss["result"]["content"][0]["text"] == "No matching notes."


def test_unknown_resource_and_uri_tricks_are_not_found():
    replies = session(*[("resources/read", {"uri": u}) for u in
                        ["notes://missing", "file:///etc/passwd", "notes://all/../../x", "", None, 5]])
    assert all(r["error"]["code"] == -32002 for r in replies)


def test_input_validation_returns_tool_errors():
    bad_args = [{"title": "", "text": "x"},                      # too short
                {"title": "t" * 51, "text": "x"},                # too long
                {"title": "t", "text": "x" * 501},               # too long
                {"title": "t", "text": 5},                       # wrong type
                {"title": "t"},                                  # missing
                {"title": "t", "text": "x", "admin": True},      # extra field
                {"title": "t", "text": "bad\x00char"}]           # control character
    replies = session(*[("tools/call", {"name": "add_note", "arguments": a}) for a in bad_args]
                      + [("tools/call", {"name": "add_note", "arguments": "not-an-object"}),
                         ("resources/read", {"uri": "notes://all"})])
    for r in replies[:-1]:
        assert r["result"]["isError"] is True and "Invalid arguments" in r["result"]["content"][0]["text"]
    notes = json.loads(replies[-1]["result"]["contents"][0]["text"])
    assert len(notes) == 1  # nothing bad was stored


def test_unknown_tool_is_a_protocol_error():
    (r,) = session(("tools/call", {"name": "drop_database", "arguments": {}}))
    assert r["error"]["code"] == -32602


def test_prompt_get_and_prompt_validation():
    ok, bad, unknown = session(("prompts/get", {"name": "summarize_notes", "arguments": {"style": "detailed"}}),
                               ("prompts/get", {"name": "summarize_notes", "arguments": {"style": "evil"}}),
                               ("prompts/get", {"name": "nope"}))
    text = ok["result"]["messages"][0]["content"]["text"]
    assert "detailed" in text and "untrusted" in text
    assert bad["error"]["code"] == -32602 and unknown["error"]["code"] == -32602


def test_validate_function_directly():
    schema = mod.TOOLS["add_note"]["inputSchema"]
    assert mod.validate(schema, {"title": "a", "text": "b"}) is None
    assert "too long" in mod.validate(schema, {"title": "a" * 60, "text": "b"})
    enum_schema = {"type": "object", "properties": {"s": {"type": "string", "enum": ["a"]}}}
    assert mod.validate(enum_schema, {"s": "b"}) == "s must be one of ['a']"


def test_note_limit():
    server = mod.NotesServer()
    server.initialized = True
    for i in range(mod.MAX_NOTES):
        server.handle(rpc(i, "tools/call", {"name": "add_note", "arguments": {"title": str(i), "text": "x"}}))
    last = server.handle(rpc(999, "tools/call", {"name": "add_note", "arguments": {"title": "z", "text": "x"}}))
    assert last["result"]["isError"] is True and len(server.notes) == mod.MAX_NOTES
