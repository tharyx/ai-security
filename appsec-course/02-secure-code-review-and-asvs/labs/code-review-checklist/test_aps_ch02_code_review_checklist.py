import re
from pathlib import Path

from aisec_lab import load_lab_module

rv = load_lab_module(__file__, "reviewer")
FIX = Path(__file__).resolve().parent / "fixtures"
VULN = rv.review_tree(FIX / "vulnerable")
FIXED = rv.review_tree(FIX / "fixed")


def rules(findings):
    return {f.rule for f in findings}


def test_vulnerable_fixture_fails_every_checklist_area():
    assert set(rv.checklist(VULN).values()) == {"FAIL"}
    assert rv.gate(VULN) == 1


def test_fixed_fixture_passes_with_zero_findings():
    assert FIXED == []
    assert set(rv.checklist(FIXED).values()) == {"PASS"} and rv.gate(FIXED) == 0


def test_sql_concatenation_found_directly_and_through_a_variable():
    lines = {f.message.split("in ")[-1] for f in VULN if f.rule == "SQL001"}
    assert lines == {"search())", "login())"}


def test_bind_parameters_with_fstring_argument_are_not_flagged():
    src = 'def f(db, q):\n    return db.execute("SELECT 1 FROM t WHERE n LIKE ?", (f"%{q}%",))\n'
    assert rv.review_python_ast(src, "x.py") == []


def test_unescaped_html_flagged_but_escaped_html_not():
    bad = 'def f(q):\n    return f"<b>{q}</b>"\n'
    good = 'def f(q):\n    return f"<b>{escape(q)}</b>"\n'
    assert rules(rv.review_python_ast(bad, "x.py")) == {"XSS001"}
    assert rv.review_python_ast(good, "x.py") == []


def test_template_safe_filter_and_innerhtml_are_flagged():
    found = [f for f in VULN if f.file.endswith("profile.html")]
    assert len(found) == 2 and rules(found) == {"XSS002"}


def test_weak_hash_and_plain_equality_on_secrets():
    assert {"AUTH001", "AUTH002", "AUTH003"} <= rules(VULN)


def test_routes_without_auth_and_idor_queries_are_flagged():
    routes = sorted(re.search(r"\((/\S*) in ", f.message).group(1) for f in VULN if f.rule == "AUTHZ001")
    assert routes == ["/account/password", "/admin/users", "/invoice/<int:invoice_id>", "/profile"]
    assert any(f.rule == "AUTHZ002" for f in VULN)


def test_regex_without_end_anchor_flagged_but_anchored_not():
    assert rules(rv.review_lines('re.match(r"[0-9]{6}", z)', "a.py")) == {"VAL001"}
    assert rv.review_lines('re.match(r"[0-9]{6}$", z)', "a.py") == []


def test_secret_from_environment_is_not_flagged():
    assert rv.review_lines('SECRET_KEY = os.environ["APP_SECRET_KEY"]', "s.py") == []


def test_misconfigurations_found():
    assert {"CONF001", "CONF002", "CONF003", "CONF004"} <= rules(VULN)


def test_report_shows_checklist_and_asvs_chapter():
    r = rv.report(VULN)
    assert "| Authorization | FAIL |" in r and "V8 Authorization" in r
