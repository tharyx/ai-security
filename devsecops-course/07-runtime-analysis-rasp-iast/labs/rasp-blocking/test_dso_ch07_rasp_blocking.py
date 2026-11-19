from aisec_lab import load_lab_module

p = load_lab_module(__file__, "protect")
tinyapp, agent_mod = p.tinyapp, p.agent_mod


def run(mode, handler, params, **kw):
    app = tinyapp.App()
    with agent_mod.IastAgent(mode=mode, **kw) as agent:
        status, body = p.handle(app, agent, handler, params)
    return app, agent, status, body


def test_sqli_blocked_in_protect_mode_and_succeeds_without_it():
    _, _, status, body = run("report", "user_by_name", {"name": "x' OR '1'='1"})
    assert status == 200 and len(body) == 2  # leaks every user
    _, agent, status, body = run("block", "user_by_name", {"name": "x' OR '1'='1"})
    assert status == 403 and "SQL_INJECTION" in body
    assert agent.findings[0].blocked


def test_benign_input_is_allowed_in_protect_mode():
    _, agent, status, body = run("block", "user_by_name", {"name": "alice"})
    assert status == 200 and body == [(1, "alice")]
    assert agent.findings[0].blocked is False  # flow recorded for developers, user not hurt


def test_hostile_text_in_bound_parameter_is_not_blocked():
    _, agent, status, _ = run("block", "user_by_id", {"id": "1' OR '1'='1"})
    assert status == 200 and agent.findings == []


def test_path_traversal_blocked_and_leaks_without_protection():
    _, _, status, body = run("report", "read_doc", {"file": "../../etc/passwd"})
    assert status == 200 and "FAKE-CANARY" in body
    _, _, status, body = run("block", "read_doc", {"file": "../../etc/passwd"})
    assert status == 403


def test_command_injection_blocked_and_never_reaches_the_shell_stub():
    app, _, status, _ = run("block", "ping", {"host": "127.0.0.1; id"})
    assert status == 403 and app.shell.executed == []


def test_monitor_only_kind_is_recorded_but_allowed():
    app, agent, status, _ = run("block", "ping", {"host": "1.1.1.1; id"}, block_kinds={"SQL_INJECTION"})
    assert status == 200 and app.shell.executed == ["ping -c 1 1.1.1.1; id"]
    assert agent.findings[0].blocked is False and agent.findings[0].malicious_payload


def test_benchmark_measures_overhead_without_changing_behaviour():
    r = p.benchmark(300)
    assert set(r["us_per_request"]) == {"no agent", "IAST report", "RASP block"}
    assert r["overhead_x"]["no agent"] == 1.0
    assert all(v > 0 for v in r["us_per_request"].values())
    assert r["overhead_x"]["RASP block"] < 500  # generous: this is a timing smoke test, not a performance claim


def test_agent_is_removed_after_the_benchmark():
    original = tinyapp.Database.execute
    p.benchmark(20)
    assert tinyapp.Database.execute is original
