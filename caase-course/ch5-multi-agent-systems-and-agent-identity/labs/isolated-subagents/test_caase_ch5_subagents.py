import pytest
from aisec_lab import load_lab_module, make_canary

m = load_lab_module(__file__, "subagents")
HR, CODE = make_canary("FAKE-HR"), make_canary("FAKE-CODE")


def setup():
    vault = m.Vault({"hr": HR, "code": CODE})
    return vault, m.Orchestrator(vault)


def test_context_is_not_shared_with_siblings_or_parent():
    vault, orch = setup()
    a = orch.spawn("hr-agent", ["read_resource", "note"], {"hr"})
    b = orch.spawn("code-agent", ["read_resource", "note"], {"code"})
    orch.parent_context.append("PARENT-SECRET-FAKE")
    a.remember(a.call("read_resource", "hr"))
    assert HR in a.context
    assert all(HR not in c for c in b.context)
    assert all("PARENT-SECRET-FAKE" not in c for c in a.context + b.context)


def test_credentials_are_per_agent_and_scoped():
    vault, orch = setup()
    a = orch.spawn("hr-agent", ["read_resource"], {"hr"})
    b = orch.spawn("code-agent", ["read_resource"], {"code"})
    assert a.credential != b.credential
    assert a.call("read_resource", "hr") == HR
    with pytest.raises(m.Denied):
        a.call("read_resource", "code")
    with pytest.raises(m.Denied):  # sibling cannot borrow a's credential through its own tool
        vault.read(b.credential, "hr")


def test_tool_allowlist_per_subagent():
    vault, orch = setup()
    a = orch.spawn("reader", ["read_resource"], {"hr"})
    with pytest.raises(m.Denied):
        a.call("note", "x")
    with pytest.raises(m.Denied):
        orch.spawn("bad", ["shell"], set())


def test_parent_gets_bounded_untrusted_summary_only():
    vault, orch = setup()
    a = orch.spawn("hr-agent", ["read_resource", "note"], {"hr"})
    a.remember("early secret " + HR)
    a.call("note", "X" * 1000)
    res = orch.collect(a)
    assert len(res["summary"]) <= 200
    assert HR not in " ".join(orch.parent_context)
    assert "UNTRUSTED" in orch.parent_context[-1]


def test_terminate_destroys_context_and_revokes_credential():
    vault, orch = setup()
    a = orch.spawn("hr-agent", ["read_resource", "note"], {"hr"})
    a.call("note", "something")
    cred = a.credential
    a.terminate()
    assert a.context == []
    with pytest.raises(m.Denied):
        a.call("note", "again")
    with pytest.raises(m.Denied):
        vault.read(cred, "hr")


def test_shared_pool_is_the_vulnerable_design():
    vault = m.Vault({"hr": HR, "code": CODE})
    pool = m.SharedPool(vault, {"hr", "code"})
    pool.run("hr-agent", "hr")
    pool.run("code-agent", "code")
    # The code-agent can see HR data in the shared context, and any agent can read anything.
    assert any(HR in c for c in pool.context)
    assert pool.run("code-agent", "hr") == HR
