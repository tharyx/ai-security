"""Mid-task goal hijack: objective substitution, and the controls that stop it."""

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "hijack")


def agent(**kw):
    return m.Agent(m.WorkLLM(), **kw)


def test_benign_run_completes_the_original_goal():
    a = agent()
    assert a.run("q3") == "FINAL: done"
    assert a.notes and a.records and a.goal_id == "summarize_report"


def test_poisoned_report_substitutes_the_objective_and_deletes_records():
    a = agent()
    a.run("q3-poisoned")
    assert a.goal_id == "hijacked" and a.records == []  # objective changed, data gone


def test_objective_lock_keeps_goal_but_allows_the_deletion_alone():
    a = agent(objective_lock=True)
    a.run("q3-poisoned")
    assert a.goal_id == "summarize_report"
    assert a.records == []  # lock alone does not stop a gullible model from calling the tool


def test_goal_tool_allowlist_blocks_off_goal_tool():
    a = agent(goal_tool_allowlist=True)
    a.run("q3-poisoned")
    assert a.records and ("delete_records", "tool not allowed for goal summarize_report") in a.trace


def test_human_approval_blocks_destructive_tool_without_a_yes():
    a = agent(approve_destructive=True, approver=lambda t, args: False)
    a.run("q3-poisoned")
    assert a.records


def test_approval_card_yes_lets_a_legitimate_destructive_call_through():
    a = agent(approve_destructive=True, approver=lambda t, args: True)
    a.run("q3-poisoned")
    assert a.records == []  # approval is only as good as the human: show the exact action and the goal


def test_all_controls_together_keep_goal_and_data():
    a = agent(objective_lock=True, goal_tool_allowlist=True, approve_destructive=True, approver=lambda t, g: False)
    a.run("q3-poisoned")
    assert a.goal_id == "summarize_report" and a.records


def test_legitimate_redirect_needs_the_signed_user_channel():
    a = agent(objective_lock=True, goal_tool_allowlist=True)
    assert a.redirect("archive_report", "n1", m.sign("archive_report", "n1"))
    assert a.goal_id == "archive_report" and a.goal_history == ["summarize_report"]


def test_forged_redirect_is_rejected():
    a = agent(objective_lock=True)
    assert not a.redirect("archive_report", "n1", "deadbeef")
    assert not a.redirect("archive_report", "n2", m.sign("archive_report", "n1"))  # wrong nonce
    assert a.goal_id == "summarize_report"
