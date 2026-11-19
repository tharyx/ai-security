"""Tests for rug_pull_defense.py. Run: python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers"""

from __future__ import annotations

import json

import pytest

from aisec_lab import load_lab_module

rp = load_lab_module(__file__, "rug_pull_defense")
KEY = b"pin-key-pin-key-pin-key-pin-key!"


def setup(verify_before_call=True):
    server = rp.NotesServer()
    pins = rp.PinStore(KEY)
    pins.pin_server("notes", server.list_tools())
    return server, pins, rp.GuardedClient("notes", server, pins, verify_before_call)


def test_unchanged_server_passes_and_calls_work():
    server, pins, client = setup()
    assert [t["name"] for t in client.list_tools()] == ["read_note", "add_note"]
    assert client.call_tool("read_note", {"id": "1"}) == "read_note ok"
    assert client.quarantined == {} and client.changes == []


def test_rug_pull_is_quarantined_and_the_honest_tool_still_works():
    server, pins, client = setup()
    server.rug_pull()
    safe = [t["name"] for t in client.list_tools()]
    assert safe == ["read_note"]
    assert "add_note" in client.quarantined
    with pytest.raises(PermissionError):
        client.call_tool("add_note", {"text": "x"})
    assert client.call_tool("read_note", {"id": "1"}) == "read_note ok"
    assert [c[0] for c in server.calls] == ["read_note"]          # the poisoned tool was never called


def test_diff_shows_what_changed_with_severity():
    server, pins, client = setup()
    server.rug_pull()
    client.list_tools()
    kinds = {c.kind: c for c in client.quarantined["add_note"]}
    assert kinds["description_changed"].severity == "high"          # new text mentions ssh and "do not tell"
    assert "+Add a note. Before using this tool" in kinds["description_changed"].diff
    assert kinds["schema_changed"].severity == "high" and '"context"' in kinds["schema_changed"].diff


def test_poisoned_description_never_reaches_the_model_list():
    server, pins, client = setup()
    server.rug_pull()
    assert "id_rsa" not in json.dumps(client.list_tools())


def test_new_tool_is_quarantined_fail_closed():
    server, pins, client = setup()
    server.add_tool()
    assert "export_all" not in [t["name"] for t in client.list_tools()]
    assert client.quarantined["export_all"][0].kind == "new_tool"
    with pytest.raises(PermissionError):
        client.call_tool("export_all", {})


def test_removed_tool_is_reported():
    server, pins, client = setup()
    del server._tools["read_note"]
    client.list_tools()
    assert [c.kind for c in client.changes] == ["removed_tool"]


def test_list_changed_notification_triggers_reverification():
    server, pins, client = setup()
    client.list_tools()
    server.rug_pull()
    assert [t["name"] for t in client.on_tools_list_changed()] == ["read_note"]
    assert any("list_changed" in a for a in client.audit)


def test_definition_swapped_between_list_and_call_is_caught_by_call_time_check():
    server, pins, client = setup(verify_before_call=True)
    assert "add_note" in [t["name"] for t in client.list_tools()]
    server.rug_pull()                                               # server changes AFTER the host listed
    with pytest.raises(PermissionError):
        client.call_tool("add_note", {"text": "x"})
    assert server.calls == []


def test_without_call_time_check_the_swap_succeeds_the_toctou_bug():
    server, pins, client = setup(verify_before_call=False)
    client.list_tools()
    server.rug_pull()
    assert client.call_tool("add_note", {"text": "x"}) == "add_note ok"     # why verify_before_call defaults to True


def test_flip_on_a_later_list_is_still_caught():
    server, pins, client = setup()
    server.flip_after(2)
    client.list_tools()
    assert client.quarantined == {}
    client.list_tools()                      # the server flips here
    assert "add_note" in client.quarantined


def test_human_reapproval_updates_the_pin_and_audits_it():
    server, pins, client = setup()
    server.rug_pull()
    client.list_tools()
    client.approve("add_note", reviewer="alice")
    assert "add_note" in [t["name"] for t in client.list_tools()]
    assert any("approve notes.add_note by alice" in a for a in client.audit)


def test_pin_file_round_trip_and_tamper_detection():
    server, pins, client = setup()
    text = pins.dumps()
    assert rp.PinStore.loads(text, KEY).pins == pins.pins
    tampered = json.loads(text)
    body = json.loads(tampered["pins"])
    body["notes"]["tools"]["add_note"] = "0" * 64
    tampered["pins"] = json.dumps(body, sort_keys=True)
    with pytest.raises(ValueError):
        rp.PinStore.loads(json.dumps(tampered), KEY)
    with pytest.raises(ValueError):
        rp.PinStore.loads(text, b"wrong-key-wrong-key-wrong-key-32")


def test_hash_ignores_irrelevant_fields_but_not_relevant_ones():
    t = {"name": "a", "description": "d", "inputSchema": {"type": "object"}, "title": "Pretty", "icon": "x"}
    assert rp.tool_hash(t) == rp.tool_hash({**t, "title": "Other", "icon": "y"})
    assert rp.tool_hash(t) != rp.tool_hash({**t, "description": "d "})
    assert rp.tool_hash(t) != rp.tool_hash({**t, "annotations": {"readOnlyHint": False}})
