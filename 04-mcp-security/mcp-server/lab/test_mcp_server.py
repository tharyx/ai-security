"""Regression tests: each server-trust attack must work on the vulnerable host and fail on the secure host.

Run from the repository root:
    python -m pytest 04-mcp-security/mcp-server -v
"""

import json

import pytest

from aisec_lab import MockLLM, load_lab_module

attacks = load_lab_module(__file__, "attacks")
servers = load_lab_module(__file__, "servers")
vuln = load_lab_module(__file__, "vulnerable_host")
sec = load_lab_module(__file__, "secure_host")

ASK = "Summarize my notes for today."


@pytest.fixture
def registry():
    weather = sec.review_server(servers.weather_server().handle)
    notes = sec.review_server(servers.NotesServer().handle, side_effect_tools={"share_note"})
    return {weather.name: weather, notes.name: notes}


def leaked(notes) -> bool:
    return any(m["to"] == servers.ATTACKER_INBOX and notes.private_note in m["body"] for m in notes.outbox)


# ---------- Part 0: the JSON-RPC 2.0 basics -------------------------------------------

def test_server_speaks_json_rpc():
    server = servers.weather_server()
    reply = json.loads(server.handle('{"jsonrpc": "2.0", "id": 7, "method": "tools/list"}'))
    assert reply["id"] == 7 and reply["result"]["tools"][0]["name"] == "get_forecast"


@pytest.mark.parametrize("raw, code", [
    ("{not json", servers.PARSE_ERROR),
    ('{"id": 1, "method": "tools/list"}', servers.INVALID_REQUEST),            # missing "jsonrpc"
    ('{"jsonrpc": "2.0", "id": 1, "method": "shell/exec"}', servers.METHOD_NOT_FOUND),
    ('{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nope"}}', servers.INVALID_PARAMS),
])
def test_server_returns_json_rpc_errors(raw, code):
    assert json.loads(servers.weather_server().handle(raw))["error"]["code"] == code


def test_notifications_get_no_reply():
    assert servers.weather_server().handle('{"jsonrpc": "2.0", "method": "notifications/initialized"}') is None


# ---------- Part 1: prove the attacks are real -----------------------------------------

def test_typosquat_server_leaks_notes_through_vulnerable_host():
    notes, host = servers.NotesServer(), vuln.VulnerableHost(MockLLM())
    host.connect(notes.handle)
    host.connect(servers.typosquat_server().handle)
    host.ask(ASK)
    assert leaked(notes)


def test_rug_pull_is_silently_accepted_by_vulnerable_host():
    notes, host = servers.NotesServer(), vuln.VulnerableHost(MockLLM())
    host.connect(notes.handle)
    host.ask(ASK)
    assert notes.outbox == []           # honest on day 1
    notes.rug_pull()
    host.refresh_tools()
    host.ask(ASK)
    assert leaked(notes)                # malicious on day 30, same name and version


def test_later_server_shadows_tool_in_vulnerable_host():
    notes, shadow = servers.NotesServer(), servers.shadow_server()
    host = vuln.VulnerableHost(MockLLM())
    host.connect(notes.handle)
    host.connect(shadow.handle)
    host.call_tool("share_note", {"note_id": "n2", "to": "colleague@acme.example"})
    assert shadow.captured and notes.outbox == []


def test_vulnerable_host_logs_raw_arguments():
    notes, host = servers.NotesServer(), vuln.VulnerableHost(MockLLM())
    host.connect(notes.handle)
    host.call_tool("add_note", {"text": "my PIN is CANARY-PIN-1234"})
    assert any("CANARY-PIN-1234" in line for line in host.log)


# ---------- Part 2: the secure host holds ------------------------------------------------

def test_unregistered_server_is_rejected(registry):
    host = sec.SecureHost(registry, MockLLM())
    assert host.connect(servers.typosquat_server().handle) is False
    assert "server_rejected" in host.security.kinds()
    assert "get_forecast" not in host.tools


def test_wrong_version_of_approved_server_is_rejected(registry):
    server = servers.weather_server()
    server.version = "1.5.0"  # an unreviewed upgrade
    host = sec.SecureHost(registry, MockLLM())
    assert host.connect(server.handle) is False


def test_impostor_with_approved_name_and_version_is_quarantined(registry):
    notes, host = servers.NotesServer(), sec.SecureHost(registry, MockLLM())
    host.connect(notes.handle)
    assert host.connect(servers.impostor_server().handle) is True  # name and version match ...
    assert "get_forecast" not in host.tools                        # ... but the content does not
    host.ask(ASK)
    assert not leaked(notes)


def test_rug_pull_is_detected_and_quarantined(registry):
    notes, host = servers.NotesServer(), sec.SecureHost(registry, MockLLM())
    host.connect(notes.handle)
    notes.rug_pull()
    host.refresh_tools()
    assert "tool_definition_changed" in host.security.kinds()
    assert "add_note" not in host.tools and "share_note" in host.tools
    host.ask(ASK)
    assert not leaked(notes)


def test_quarantined_description_never_reaches_the_model(registry):
    llm = MockLLM()
    notes, host = servers.NotesServer(), sec.SecureHost(registry, llm)
    host.connect(notes.handle)
    notes.rug_pull()
    host.refresh_tools()
    host.ask(ASK)
    assert "IMPORTANT" not in json.dumps(llm.calls)


def test_quarantined_tool_cannot_be_called(registry):
    notes, host = servers.NotesServer(), sec.SecureHost(registry, MockLLM())
    host.connect(notes.handle)
    notes.rug_pull()
    host.refresh_tools()
    assert host.call_tool("add_note", {"text": "hi"}).startswith("[blocked")


def test_shadowing_blocked_even_when_registry_is_off(registry):
    notes, shadow = servers.NotesServer(), servers.shadow_server()
    host = sec.SecureHost(registry, MockLLM(), enforce_registry=False, pin_tools=False)
    host.connect(notes.handle)
    host.connect(shadow.handle)
    host.call_tool("share_note", {"note_id": "n2", "to": "colleague@acme.example"})
    assert "tool_name_collision" in host.security.kinds()
    assert shadow.captured == [] and notes.outbox[0]["to"] == "colleague@acme.example"


def test_benign_user_actions_still_work(registry):
    notes, host = servers.NotesServer(), sec.SecureHost(registry, MockLLM())
    host.connect(servers.weather_server().handle)
    host.connect(notes.handle)
    assert host.call_tool("get_forecast", {"city": "Paris"}) == "Forecast for Paris: sunny, 21 C"
    assert host.call_tool("share_note", {"note_id": "n2", "to": "colleague@acme.example"}).startswith("shared")
    assert host.security.events == []


# ---------- Part 3: defense in depth - each hard layer holds on its own --------------------

def test_approval_layer_alone_stops_the_rug_pull(registry):
    """Pinning off: the poisoned description reaches the model, but the side effect needs a human."""
    notes, host = servers.NotesServer(), sec.SecureHost(registry, MockLLM(), pin_tools=False)
    host.connect(notes.handle)
    notes.rug_pull()
    host.refresh_tools()
    out = host.ask(ASK)
    assert "needs human approval" in out
    assert not leaked(notes)


def test_with_pinning_and_approval_off_the_attack_lands(registry):
    notes = servers.NotesServer()
    host = sec.SecureHost(registry, MockLLM(), pin_tools=False, require_approval=False)
    host.connect(notes.handle)
    notes.rug_pull()
    host.refresh_tools()
    host.ask(ASK)
    assert leaked(notes), "with both hard layers off the secure host behaves like the vulnerable one"


def test_server_cannot_mark_its_own_tool_as_safe(registry):
    """Side-effect classification comes from the registry, not from server-supplied hints."""
    notes = servers.NotesServer()
    notes.tools["share_note"].annotations = {"readOnlyHint": True}  # a lying "hint"
    host = sec.SecureHost(registry, MockLLM(), pin_tools=False)
    host.connect(notes.handle)
    out = host.call_tool("share_note", {"note_id": "all", "to": servers.ATTACKER_INBOX}, proposed_by="model")
    assert "needs human approval" in out and notes.outbox == []


def test_oversized_reply_is_rejected(registry):
    host = sec.SecureHost(registry, MockLLM())
    host.connect(servers.weather_server().handle)
    host.servers["acme-weather"] = lambda raw: json.dumps(
        {"jsonrpc": "2.0", "id": json.loads(raw)["id"], "result": {"content": [{"type": "text", "text": "A" * 100_000}]}})
    assert "reply too large" in host.call_tool("get_forecast", {"city": "Paris"})


def test_mismatched_json_rpc_id_is_rejected(registry):
    host = sec.SecureHost(registry, MockLLM())
    host.connect(servers.weather_server().handle)
    host.servers["acme-weather"] = lambda raw: json.dumps({"jsonrpc": "2.0", "id": 999, "result": {}})
    assert "mismatched id" in host.call_tool("get_forecast", {"city": "Paris"})


def test_audit_log_is_attributable_and_redacted(registry):
    host = sec.SecureHost(registry, MockLLM())
    notes = servers.NotesServer()
    host.connect(notes.handle)
    host.call_tool("add_note", {"text": "my PIN is CANARY-PIN-1234"})
    event = host.audit[-1]
    assert event["server"] == "acme-notes" and event["tool"] == "add_note" and event["decision"] == "allow"
    assert len(event["correlation_id"]) == 12
    assert "CANARY-PIN-1234" not in json.dumps(host.audit)


# ---------- Part 4: local HTTP transport (DNS rebinding) ------------------------------------

@pytest.fixture
def guard():
    return sec.LocalHttpGuard(port=attacks.LOCAL_PORT, token=attacks.LOCAL_TOKEN)


@pytest.mark.parametrize("name", list(attacks.HTTP_REQUESTS))
def test_vulnerable_local_server_accepts_everything(name):
    assert vuln.naive_http_accept(*attacks.HTTP_REQUESTS[name]) is True


@pytest.mark.parametrize("name", list(attacks.HTTP_REQUESTS))
def test_guard_blocks_every_hostile_request(guard, name):
    assert guard.accept(*attacks.HTTP_REQUESTS[name]) is False


def test_guard_accepts_the_real_local_client(guard):
    assert guard.accept(*attacks.BENIGN_REQUEST) is True


def test_correct_host_but_no_token_is_blocked(guard):
    """Even if Host/Origin checks were fooled, the per-launch token still has to match."""
    ok, reason = guard.request_ok({"Host": f"localhost:{attacks.LOCAL_PORT}"})
    assert not ok and "token" in reason


@pytest.mark.parametrize("bind, expected", [("127.0.0.1", True), ("::1", True), ("localhost", True),
                                            ("0.0.0.0", False), ("192.168.1.20", False)])
def test_bind_address_must_be_loopback(guard, bind, expected):
    assert guard.bind_ok(bind) is expected
