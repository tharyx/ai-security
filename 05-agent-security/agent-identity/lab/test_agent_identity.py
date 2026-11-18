"""Regression tests: each identity attack works on the shared-key runtime and fails on the secure one.

Run from the repository root:
    python -m pytest 05-agent-security/agent-identity -v
"""

import pytest

from aisec_lab import MockLLM, load_lab_module

attacks = load_lab_module(__file__, "attacks")
vuln = load_lab_module(__file__, "vulnerable_runtime")
sec = load_lab_module(__file__, "secure_runtime")

SUMMARIZE = "Summarize this report."


def secure(**kw):
    return sec.SecureAgentRuntime(llm=MockLLM(), **kw)


# ---------- Part 1: prove the attacks are real -------------------------------------

def test_injected_tool_call_deletes_a_bucket_with_the_shared_admin_key():
    rt = vuln.VulnerableAgentRuntime(llm=MockLLM())
    rt.run("summarizer", "alice", SUMMARIZE, attacks.POISONED_REPORT)
    assert "customer-backups" not in rt.cloud.buckets


def test_confused_deputy_leaks_payroll_to_a_user_without_finance_access():
    rt = vuln.VulnerableAgentRuntime(llm=MockLLM())
    assert vuln.PAYROLL_CANARY in rt.run("summarizer", "alice", attacks.CONFUSED_DEPUTY_TASK)


def test_vulnerable_log_cannot_say_which_user_or_agent_acted():
    rt = vuln.VulnerableAgentRuntime(llm=MockLLM())
    rt.run("summarizer", "alice", SUMMARIZE, attacks.POISONED_REPORT)
    line = rt.cloud.log[-1]
    assert "alice" not in line and "summarizer" not in line
    del rt.cloud.log[-1]  # an insider hides it ...
    assert rt.cloud.log == []  # ... and nothing can tell that a line ever existed


# ---------- Part 2: the secure runtime holds ---------------------------------------

def test_injected_delete_is_denied_by_token_scope():
    rt = secure()
    out = rt.run(rt.start_session("alice", "summarizer"), SUMMARIZE, attacks.POISONED_REPORT)
    assert out.startswith("403")
    assert rt.cloud.buckets == set(sec.BUCKETS)


def test_confused_deputy_is_denied():
    rt = secure()
    out = rt.run(rt.start_session("alice", "summarizer"), attacks.CONFUSED_DEPUTY_TASK)
    assert sec.PAYROLL_CANARY not in out
    assert out.startswith("403")


def test_finance_user_can_still_read_payroll_through_the_same_agent():
    rt = secure()
    out = rt.run(rt.start_session("bob", "summarizer"), attacks.CONFUSED_DEPUTY_TASK)
    assert sec.PAYROLL_CANARY in out  # authorized human: the deputy works as intended


def test_token_expires_so_a_replayed_credential_is_useless():
    clock = sec.FakeClock()
    rt = secure(clock=clock)
    token = rt.start_session("bob", "ticket-bot").token
    assert rt.cloud.call(token, "create_ticket", {"title": "ok"}) == "ticket created"
    clock.advance(attacks.REPLAY_AFTER_SECONDS)
    assert rt.cloud.call(token, "create_ticket", {"title": "replay"}) == "401 token expired"


def test_tampered_token_fails_signature_check():
    rt = secure()
    forged = attacks.tamper_token(rt.start_session("alice", "summarizer").token)
    assert rt.cloud.call(forged, *attacks.STOLEN_CALL) == "401 bad signature"


@pytest.mark.parametrize("junk", ["", "not-a-token", "a.b.c", "e30.AAAA"])
def test_malformed_tokens_are_rejected(junk):
    assert secure().cloud.call(junk, "read_report", {"name": "alice-q3-summary"}).startswith("401")


def test_wrong_audience_is_rejected():
    rt = secure()
    other = rt.tokens.mint(user="bob", agent="ticket-bot", session="s", scopes={"tickets:write"},
                           audience="https://mail.acme.example")
    assert rt.cloud.call(other, "create_ticket", {"title": "x"}) == "401 wrong audience"


def test_delegation_cannot_widen_scope():
    rt = secure()
    planner = rt.start_session("alice", "planner")
    with pytest.raises(sec.TokenError):
        rt.delegate(planner, "storage-janitor", {"storage:admin"})  # alice's planner lacks it


def test_exchange_refuses_widening_even_if_the_runtime_check_is_skipped():
    rt = secure(scoped=False)  # registry check off; token exchange still enforces subset
    planner = rt.tokens.mint(user="alice", agent="planner", session="s1", scopes={"reports:read"})
    with pytest.raises(sec.TokenError, match="scope widening"):
        rt.tokens.exchange(planner, actor="ticket-bot", scopes={"reports:read", "storage:admin"})


def test_delegated_token_carries_the_full_actor_chain_and_never_outlives_parent():
    clock = sec.FakeClock()
    rt = secure(clock=clock)
    planner = rt.start_session("bob", "planner")
    clock.advance(200)
    janitor = rt.delegate(planner, "storage-janitor", {"storage:admin"})
    claims = rt.tokens.verify(janitor.token, audience=sec.CLOUD_AUDIENCE)
    assert sec.actor_chain(claims) == ["bob", "planner", "storage-janitor"]
    parent = rt.tokens.verify(planner.token, audience=sec.CLOUD_AUDIENCE)
    assert claims["exp"] == parent["exp"]


def test_revoked_session_and_killed_agent_stop_working():
    rt = secure()
    s1 = rt.start_session("alice", "ticket-bot")
    rt.end_session(s1)
    assert rt.cloud.call(s1.token, "create_ticket", {"title": "x"}) == "401 token revoked"
    s2 = rt.start_session("bob", "planner")
    janitor = rt.delegate(s2, "storage-janitor", {"storage:admin"})
    rt.kill_agent("planner")  # kills every token whose chain includes the planner
    assert "agent disabled" in rt.cloud.call(janitor.token, *attacks.STOLEN_CALL)


def test_audit_log_attributes_user_and_agent_chain():
    rt = secure()
    janitor = rt.delegate(rt.start_session("bob", "planner"), "storage-janitor", {"storage:admin"})
    rt.run(janitor, 'CALL_TOOL delete_bucket {"bucket": "build-cache"}')
    assert rt.who_did("delete_bucket") == ["bob -> planner -> storage-janitor (session sess-0001)"]


def test_audit_chain_detects_edits_and_deletions():
    rt = secure()
    sess = rt.start_session("bob", "ticket-bot")
    for i in range(3):
        rt.cloud.call(sess.token, "create_ticket", {"title": f"t{i}"})
    assert rt.audit.verify() is None
    rt.audit.entries[2]["args"] = {"title": "innocent"}  # edit
    assert rt.audit.verify() == "chain broken at entry 2"
    rt2 = secure()
    sess = rt2.start_session("bob", "ticket-bot")
    for i in range(3):
        rt2.cloud.call(sess.token, "create_ticket", {"title": f"t{i}"})
    del rt2.audit.entries[1]  # delete from the middle
    assert rt2.audit.verify() is not None


def test_truncation_needs_an_external_anchor():
    rt = secure()
    sess = rt.start_session("bob", "ticket-bot")
    rt.cloud.call(sess.token, "create_ticket", {"title": "x"})
    anchor = rt.audit.anchor()
    rt.audit.entries.pop()  # drop the newest entry: the remaining chain is still valid
    assert rt.audit.verify() is None
    assert "anchor" in rt.audit.verify(anchor)


def test_denials_are_audited_too():
    rt = secure()
    rt.run(rt.start_session("alice", "summarizer"), SUMMARIZE, attacks.POISONED_REPORT)
    denied = [e for e in rt.audit.entries if e["decision"] == "deny"]
    assert denied and denied[0]["chain"] == ["alice", "summarizer"]


# ---------- Part 3: each hard layer holds on its own ---------------------------------

def test_user_check_alone_stops_confused_deputy():
    rt = secure(scoped=False)  # token says "*" - an over-scoped token, as if by a bug
    out = rt.run(rt.start_session("alice", "summarizer"), attacks.CONFUSED_DEPUTY_TASK)
    assert out == "403 user alice lacks finance:read"


def test_agent_scope_alone_protects_a_powerful_user():
    rt = secure(check_user=False)
    out = rt.run(rt.start_session("bob", "summarizer"), SUMMARIZE, attacks.POISONED_REPORT)
    assert out == "403 token lacks scope storage:admin"  # bob may delete; his summarizer may not


def test_with_scope_and_user_checks_off_the_deputy_is_confused_again():
    rt = secure(scoped=False, check_user=False)
    assert sec.PAYROLL_CANARY in rt.run(rt.start_session("alice", "summarizer"),
                                         attacks.CONFUSED_DEPUTY_TASK)


def test_long_lived_tokens_bring_replay_back():
    clock = sec.FakeClock()
    rt = secure(short_lived=False, clock=clock)
    token = rt.start_session("bob", "ticket-bot").token
    clock.advance(7 * 24 * 3600)  # a week later
    assert rt.cloud.call(token, "create_ticket", {"title": "replay"}) == "ticket created"


def test_live_permission_change_takes_effect_before_token_expiry():
    rt = secure(scoped=False)
    token = rt.start_session("bob", "ticket-bot").token
    rt.cloud.user_permissions["bob"].discard("tickets:write")  # bob changes team
    assert rt.cloud.call(token, "create_ticket", {"title": "x"}) == "403 user bob lacks tickets:write"


# ---------- Part 4: benign path -----------------------------------------------------

def test_benign_request_still_works():
    rt = secure()
    out = rt.run(rt.start_session("alice", "summarizer"), attacks.BENIGN_TASK)
    assert out.startswith("Q3 support volume")
    assert [e["decision"] for e in rt.audit.entries] == ["session_start", "allow"]
    assert rt.audit.verify() is None
