from __future__ import annotations

import pytest

from aisec_lab import load_lab_module

a2a = load_lab_module(__file__, "a2a_lite")


@pytest.fixture()
def running():
    agent = a2a.make_summarizer()
    srv, url = a2a.serve(agent)
    yield agent, url
    srv.shutdown()


def test_agent_card_discovery_over_http(running):
    agent, url = running
    card = a2a.A2AClient(url).discover()
    assert card["name"] == "summarizer-agent"
    assert {s["id"] for s in card["skills"]} == {"summarize", "shout"}
    assert card["url"].startswith("http://127.0.0.1:")
    assert "securitySchemes" in card


def test_task_lifecycle_and_artifact(running):
    _, url = running
    c = a2a.A2AClient(url)
    t = c.send("summarize", "First idea. Second idea.")
    assert t["statusLog"] == ["submitted", "working", "completed"]
    assert t["artifacts"][0]["parts"][0]["text"] == "First idea."
    assert c.get(t["id"])["status"]["state"] == "completed"
    assert c.wait(t["id"])["status"]["state"] == "completed"


def test_input_required_then_follow_up(running):
    _, url = running
    c = a2a.A2AClient(url)
    t = c.send("summarize", "")
    assert t["status"]["state"] == "input-required"
    t2 = c.send("summarize", "Now there is text. More.", task_id=t["id"])
    assert t2["status"]["state"] == "completed"
    assert t2["statusLog"] == ["submitted", "working", "input-required", "working", "completed"]


def test_client_refuses_skill_not_in_card(running):
    _, url = running
    with pytest.raises(RuntimeError, match="does not advertise"):
        a2a.A2AClient(url).send("delete_everything", "x")


def test_server_rejects_unknown_skill_even_without_client_check(running):
    _, url = running
    c = a2a.A2AClient(url)
    with pytest.raises(RuntimeError, match="unknown skill"):
        c._rpc("message/send", {"message": {"parts": [a2a.text_part("x")], "metadata": {"skill": "nope"}}})


def test_json_rpc_errors_in_process():
    agent = a2a.make_summarizer()
    assert agent.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "nope"})["error"]["code"] == -32601
    assert agent.handle_rpc({"id": 1})["error"]["code"] == -32600
    assert agent.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tasks/get", "params": {"id": "zzz"}})["error"]["code"] == -32001
    r = agent.handle_rpc({"jsonrpc": "2.0", "id": 3, "method": "message/send", "params": {"message": {"parts": []}}})
    assert r["error"]["code"] == -32602


def test_state_machine_blocks_illegal_transitions():
    agent = a2a.make_summarizer()
    r = agent.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {
        "message": {"parts": [a2a.text_part("Hi there.")], "metadata": {"skill": "summarize"}}}})
    tid = r["result"]["id"]
    r2 = agent.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tasks/cancel", "params": {"id": tid}})
    assert "illegal transition" in r2["error"]["message"]  # a completed task cannot be canceled


def test_failed_skill_marks_task_failed_not_server_down():
    agent = a2a.A2AAgent("x", "x", {"boom": lambda t: 1 / 0})
    r = agent.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {
        "message": {"parts": [a2a.text_part("go")], "metadata": {"skill": "boom"}}}})
    assert r["result"]["status"]["state"] == "failed"
