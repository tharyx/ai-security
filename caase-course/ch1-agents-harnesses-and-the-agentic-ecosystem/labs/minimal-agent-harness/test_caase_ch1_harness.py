from aisec_lab import MockLLM, load_lab_module, make_canary

h = load_lab_module(__file__, "harness")

TASK = 'CALL_TOOL read_note {"name": "q3"}'


def poisoned_world(canary):
    return h.World(notes={"q3": h.attack_note(canary)})


def test_parser_handles_prose_fences_and_nesting():
    assert h.parse_tool_call('{"tool":"add","args":{"a":1,"b":2}}') == ("add", {"a": 1, "b": 2})
    assert h.parse_tool_call('Sure!\n```json\n{"tool": "read_note", "args": {"name": "a}b"}}\n```') == (
        "read_note", {"name": "a}b"})
    assert h.parse_tool_call("just text, no call") is None
    assert h.parse_tool_call('{"tool": 5}') is None
    assert h.parse_tool_call('{"broken": ') is None


def test_default_backend_is_the_mock_model():
    assert isinstance(h.AgentHarness(h.World()).llm, MockLLM)


def test_plan_act_observe_loop_with_scripted_model():
    w = h.World(notes={"q3": "ship the beta"})
    llm = h.ScriptedLLM(["PLAN: read then add", '{"tool":"read_note","args":{"name":"q3"}}',
                         '{"tool":"add","args":{"a":2,"b":40}}', "FINAL: done 42"])
    res = h.AgentHarness(w, llm=llm).run("go")
    assert res.stop_reason == "final" and res.final == "done 42"
    assert res.plan == "PLAN: read then add"
    assert [e["tool"] for e in res.log if e["event"] == "tool_call"] == ["read_note", "add"]
    # the observation was fed back to the model on the next step
    assert any("TOOL_RESULT read_note: ship the beta" in m["content"] for m in llm.calls[-1])


def test_step_budget_stops_a_runaway_model():
    llm = h.ScriptedLLM([f'{{"tool":"add","args":{{"a":{i},"b":1}}}}' for i in range(50)])
    res = h.AgentHarness(h.World(), llm=llm, max_steps=4).run("loop forever")
    assert res.stop_reason == "step_budget" and res.steps == 4
    assert len([e for e in res.log if e["event"] == "tool_call"]) == 4


def test_repeated_identical_call_is_detected():
    llm = h.ScriptedLLM(['{"tool":"add","args":{"a":1,"b":1}}'] * 5)
    res = h.AgentHarness(h.World(), llm=llm, max_steps=10, plan_first=False).run("x")
    assert res.stop_reason == "loop_detected" and res.steps == 2


def test_naive_harness_lets_injected_note_exfiltrate():
    canary = make_canary("FAKE")
    w = poisoned_world(canary)
    res = h.AgentHarness(w).run(TASK)
    assert w.outbox and w.outbox[0]["to"] == "attacker@evil.example"
    assert canary in w.outbox[0]["body"]
    assert res.stop_reason in ("loop_detected", "step_budget")


def test_guarded_harness_blocks_the_same_attack():
    canary = make_canary("FAKE")
    w = poisoned_world(canary)
    pol = h.GuardPolicy(allowed_tools={"read_note", "add", "send_email"})
    res = h.AgentHarness(w, policy=pol).run(TASK)
    assert w.outbox == []
    denied = [e for e in res.log if e["event"] == "denied"]
    assert denied and "untrusted" in denied[0]["reason"]


def test_domain_allowlist_applies_even_without_taint():
    pol = h.GuardPolicy(allowed_tools={"send_email"})
    assert pol.check("send_email", {"to": "x@evil.example", "body": "hi"}, tainted=False)[0] is False
    assert pol.check("send_email", {"to": "x@corp.example", "body": "hi"}, tainted=False)[0] is True


def test_guard_rejects_unknown_tool_extra_args_and_wrong_types():
    pol = h.GuardPolicy(allowed_tools={"add", "read_note"})
    assert not pol.check("delete_note", {"name": "q3"}, False)[0]
    assert not pol.check("add", {"a": 1, "b": 2, "c": 3}, False)[0]
    assert not pol.check("add", {"a": "1", "b": 2}, False)[0]
    assert not pol.check("add", {"a": True, "b": 2}, False)[0]
    assert pol.check("add", {"a": 1, "b": 2}, False)[0]


def test_naive_harness_runs_unlisted_tools_and_survives_bad_arguments():
    w = h.World(notes={"keep": "x"})
    llm = h.ScriptedLLM(['{"tool":"delete_note","args":{"name":"keep"}}', "FINAL: ok"])
    h.AgentHarness(w, llm=llm, plan_first=False).run("tidy")
    assert w.deleted == ["keep"]  # nothing stopped it
    llm = h.ScriptedLLM(['{"tool":"add","args":{"zzz":1}}', "FINAL: ok"])
    res = h.AgentHarness(w, llm=llm, plan_first=False).run("x")
    assert any("TOOL_ERROR" in str(e.get("result", "")) for e in res.log)


def test_log_records_every_step_with_event_names():
    llm = h.ScriptedLLM(['{"tool":"add","args":{"a":1,"b":2}}', "FINAL: 3"])
    res = h.AgentHarness(h.World(), llm=llm, plan_first=False).run("x")
    assert [e["event"] for e in res.log] == ["model_reply", "tool_call", "model_reply", "final"]
