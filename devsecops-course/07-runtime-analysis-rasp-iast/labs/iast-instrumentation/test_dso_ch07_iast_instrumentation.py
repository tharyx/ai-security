import pytest

from aisec_lab import load_lab_module

taint = load_lab_module(__file__, "taint")
tinyapp = load_lab_module(__file__, "tinyapp")
agent_mod = load_lab_module(__file__, "agent")
qa = load_lab_module(__file__, "qa_suite")
Request = tinyapp.Request


def run(suite):
    app = tinyapp.App()
    with agent_mod.IastAgent() as agent:
        qa.run_suite(app, agent, suite)
    return agent


def test_taint_propagates_through_concat_and_format():
    t = taint.TaintedStr("x", "request.args['a']")
    assert taint.is_tainted("pre " + t) and taint.is_tainted(t + " post") and taint.is_tainted("a %s b" % t)
    assert ("pre ", None) in ("pre " + t).parts
    assert not taint.is_tainted("plain")


def test_taint_lost_by_fstring_and_removed_by_int():
    t = taint.TaintedStr("7", "request.args['id']")
    assert not taint.is_tainted(f"id={t}")
    assert not taint.is_tainted(taint.sanitize_int(t))  # int


def test_current_suite_finds_sql_and_command_injection_flows():
    agent = run(qa.CURRENT_SUITE)
    kinds = {f.kind for f in agent.report()}
    assert kinds == {"SQL_INJECTION", "COMMAND_INJECTION"}


def test_trace_goes_source_to_sink_with_locations():
    agent = run(qa.CURRENT_SUITE)
    f = next(f for f in agent.report() if f.kind == "SQL_INJECTION")
    assert f.trace[0] == "SOURCE   request.args['name']"
    assert any(s.startswith("PROPAGATE concat at tinyapp.py:user_by_name:") for s in f.trace)
    assert f.trace[-1].startswith("SINK     Database.execute called at tinyapp.py:user_by_name:")
    assert f.endpoint == "test_find_user_by_name"


def test_harmless_input_still_reports_the_flow():
    agent = run(qa.CURRENT_SUITE)
    assert all(not f.malicious_payload for f in agent.report())


def test_safe_parameterized_query_is_not_reported():
    agent = run([qa.test_find_user_by_id])
    assert agent.report() == [] and agent.sink_calls == 1


def test_coverage_depends_on_the_tests():
    assert "PATH_TRAVERSAL" not in {f.kind for f in run(qa.CURRENT_SUITE).report()}
    assert "PATH_TRAVERSAL" in {f.kind for f in run(qa.FULL_SUITE).report()}


def test_fstring_flow_is_a_false_negative():
    app = tinyapp.App()
    with agent_mod.IastAgent() as agent:
        app.user_by_name_fstring(Request({"name": "alice"}))
    assert agent.report() == []


def test_uninstall_restores_original_methods():
    original = tinyapp.Database.execute
    with agent_mod.IastAgent():
        assert tinyapp.Database.execute is not original
    assert tinyapp.Database.execute is original


def test_report_mode_never_blocks_even_a_real_payload():
    app = tinyapp.App()
    with agent_mod.IastAgent(mode="report") as agent:
        rows = app.user_by_name(Request({"name": "x' OR '1'='1"}))
    assert len(rows) == 2  # the injection works: IAST observes, it does not stop it
    assert agent.report()[0].malicious_payload
