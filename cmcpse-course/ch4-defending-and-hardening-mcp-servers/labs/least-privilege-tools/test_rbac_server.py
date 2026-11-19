"""Tests for rbac_server.py. Run: python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers"""

from __future__ import annotations

from aisec_lab import load_lab_module

rs = load_lab_module(__file__, "rbac_server")
VIEWER, ANALYST, ADMIN = rs.Session("v", "viewer"), rs.Session("a", "analyst"), rs.Session("r", "admin")


def rpc(server, session, method, **params):
    return server.handle(session, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def names(resp):
    return sorted(t["name"] for t in resp["result"]["tools"])


def test_tools_list_is_filtered_by_role():
    s = rs.NotesServer()
    assert names(rpc(s, VIEWER, "tools/list")) == ["notes_read", "notes_search"]
    assert "notes_write" in names(rpc(s, ANALYST, "tools/list"))
    assert "notes_delete" not in names(rpc(s, ANALYST, "tools/list"))
    assert len(names(rpc(s, ADMIN, "tools/list"))) == 5


def test_hidden_tool_is_also_blocked_at_call_time():
    s = rs.NotesServer()
    r = rpc(s, VIEWER, "tools/call", name="notes_delete", arguments={"id": "notes://public/welcome"})
    assert r["error"]["code"] == rs.FORBIDDEN
    assert "notes://public/welcome" in s.store
    assert s.audit[-1]["decision"] == "deny"


def test_filtering_alone_is_not_enough_the_classic_bug():
    s = rs.NotesServer(enforce_calls=False)
    assert "notes_delete" not in names(rpc(s, VIEWER, "tools/list"))
    r = rpc(s, VIEWER, "tools/call", name="notes_delete", arguments={"id": "notes://public/welcome"})
    assert "result" in r and "notes://public/welcome" not in s.store     # the viewer deleted it


def test_unknown_role_and_missing_role_get_nothing():
    s = rs.NotesServer()
    for role in ("superuser", None, ""):
        sess = rs.Session("x", role)
        assert names(rpc(s, sess, "tools/list")) == []
        assert rpc(s, sess, "tools/call", name="notes_read", arguments={"id": "notes://public/welcome"})["error"]["code"] == rs.FORBIDDEN
        assert rpc(s, sess, "resources/list")["result"]["resources"] == []


def test_resource_scoping_list_and_read():
    s = rs.NotesServer()
    assert [r["uri"] for r in rpc(s, VIEWER, "resources/list")["result"]["resources"]] == ["notes://public/welcome"]
    assert len(rpc(s, ADMIN, "resources/list")["result"]["resources"]) == 3
    assert rpc(s, VIEWER, "resources/read", uri="notes://team/roadmap")["error"]["code"] == rs.FORBIDDEN
    assert rpc(s, ANALYST, "resources/read", uri="notes://team/roadmap")["result"]["contents"][0]["text"].startswith("Roadmap")


def test_path_tricks_cannot_escape_a_resource_scope():
    s = rs.NotesServer()
    for uri in ("notes://public/../admin/payroll", "notes://public/%2e%2e/admin/payroll", "notes://public/../../etc/passwd",
                "file:///etc/passwd"):
        assert rpc(s, VIEWER, "resources/read", uri=uri)["error"]["code"] == rs.FORBIDDEN, uri


def test_read_tool_cannot_bypass_resource_scope():
    s = rs.NotesServer()
    r = rpc(s, VIEWER, "tools/call", name="notes_read", arguments={"id": "notes://admin/payroll"})
    assert r["error"]["code"] == rs.FORBIDDEN


def test_search_never_returns_forbidden_resources_and_respects_limits():
    s = rs.NotesServer()
    hits = rpc(s, VIEWER, "tools/call", name="notes_search", arguments={"query": "notes://"})["result"]["content"][0]["text"]
    assert "payroll" not in hits and "roadmap" not in hits
    assert s.limit(ANALYST, "notes_search", "max_results", 10) == 20
    assert s.limit(VIEWER, "notes_search", "max_results", 10) == 10


def test_schema_rejects_extra_and_missing_arguments():
    s = rs.NotesServer()
    assert rpc(s, ADMIN, "tools/call", name="notes_read", arguments={"id": "notes://public/welcome", "role": "admin"})["error"]["code"] == rs.INVALID_PARAMS
    assert rpc(s, ADMIN, "tools/call", name="notes_write", arguments={"id": "x"})["error"]["code"] == rs.INVALID_PARAMS


def test_role_cannot_be_chosen_by_the_caller_through_arguments():
    s = rs.NotesServer()
    r = rpc(s, VIEWER, "tools/call", name="notes_search", arguments={"query": "x", "role": "admin"})
    assert r["error"]["code"] == rs.INVALID_PARAMS


def test_every_decision_is_audited():
    s = rs.NotesServer()
    rpc(s, VIEWER, "tools/call", name="notes_search", arguments={"query": "w"})
    rpc(s, VIEWER, "tools/call", name="notes_export", arguments={})
    assert [(e["target"], e["decision"]) for e in s.audit] == [("notes_search", "allow"), ("notes_export", "deny")]


def test_policy_has_no_tool_that_does_not_exist():
    pol = rs.load_policy()
    for role in pol["roles"].values():
        assert set(role["tools"]) <= set(rs.TOOL_DEFS)
