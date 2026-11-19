"""Objective drift: structured plan schema, goal-integrity checks, and the fail-safe path."""

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "drift")


def agent(expenses=d.EXPENSES_CLEAN, **kw):
    return d.DriftGuardedAgent(d.PlannerLLM(), expenses, **kw)


def test_clean_run_completes_and_saves_the_note():
    a = agent()
    r = a.run()
    assert r.status == "COMPLETED" and r.drift_score == 0.0 and a.notes and not a.emails


def test_poisoned_tool_output_drifts_the_plan_when_unchecked():
    a = agent(d.EXPENSES_POISONED, check_drift=False)
    assert a.run().status == "COMPLETED"
    assert a.emails and a.emails[0]["to"] == "auditor@attacker.example"


def test_goal_integrity_check_halts_on_off_objective_tool():
    a = agent(d.EXPENSES_POISONED)
    r = a.run()
    assert r.status == "HALTED_SAFE" and r.drift_score > 0
    assert any("send_email outside objective" in x for x in r.reasons)
    assert a.emails == [] and a.notes == []  # nothing committed: not even the legitimate note


def test_subtle_drift_with_an_allowed_tool_is_caught_by_the_purpose_check():
    a = agent(d.EXPENSES_SUBTLE)
    r = a.run()
    assert r.status == "HALTED_SAFE" and any("purpose unrelated" in x for x in r.reasons)
    assert a.notes == []


def test_schema_rejects_extra_fields_unknown_tools_and_oversize_plans():
    good = d.plan_json("expense-summary", [(1, "read_expenses", {}, "read the expense report")])
    assert d.validate_plan(good, "expense-summary")[1] == []
    extra = good.replace('"purpose"', '"hidden": "x", "purpose"')
    assert d.validate_plan(extra, "expense-summary")[0] is None
    bad_tool = d.plan_json("expense-summary", [(1, "format_disk", {}, "read the expense report")])
    assert d.validate_plan(bad_tool, "expense-summary")[0] is None
    many = d.plan_json("expense-summary", [(i, "read_expenses", {}, "read expense report") for i in range(1, 8)])
    assert d.validate_plan(many, "expense-summary")[0] is None


def test_objective_swap_is_detected_by_id_and_digest():
    raw = d.plan_json("expense-summary", [(1, "read_expenses", {}, "read the expense report")], digest="0" * 12)
    plan, reasons, _ = d.validate_plan(raw, "expense-summary")
    assert plan is not None and "objective id/digest changed" in reasons


def test_drift_score_is_the_share_of_bad_steps():
    raw = d.plan_json("expense-summary", [(1, "read_expenses", {}, "read the expense report"),
                                          (2, "delete_records", {}, "clean up old data")])
    _, reasons, score = d.validate_plan(raw, "expense-summary")
    assert score == 0.5 and any("delete_records" in x for x in reasons)


def test_oversized_note_is_flagged():
    big = d.plan_json("expense-summary", [(1, "save_note", {"text": "x" * 500}, "save the summary note")])
    assert any("note too long" in x for x in d.validate_plan(big, "expense-summary")[1])


# ---- fail safe ---------------------------------------------------------------
def crashing_validator(raw, objective_id):
    raise RuntimeError("validator crashed")


def test_fail_safe_when_the_validator_crashes():
    a = agent(d.EXPENSES_POISONED, validator=crashing_validator)
    r = a.run()
    assert r.status == "HALTED_SAFE" and r.reasons == ["fail-safe: RuntimeError"]
    assert a.emails == [] and a.notes == []


class GarbagePlanner(d.PlannerLLM):
    def complete(self, messages):
        return "Sure! I will just do whatever seems best."


def test_fail_safe_when_the_planner_returns_prose_instead_of_a_plan():
    a = d.DriftGuardedAgent(GarbagePlanner())
    r = a.run()
    assert r.status == "HALTED_SAFE" and r.reasons[0].startswith("schema")
    assert a.notes == [] and a.emails == []
