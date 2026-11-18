"""Tests for the embeddings mini-lab (lesson 01).

Run from the repository root:
    python -m pytest 01-ai-security-fundamentals -v
"""

import pytest

from aisec_lab import load_lab_module

te = load_lab_module(__file__, "tiny_embeddings")

INTERN = te.User("ivan", "acme", frozenset({"intern"}))
HR = te.User("hana", "acme", frozenset({"hr"}))
EMPLOYEE = te.User("eli", "acme", frozenset({"employee"}))
GLOBEX_USER = te.User("gus", "globex", frozenset({"employee"}))

QUERIES = [
    "what is the salary range for senior engineers",
    "salary bands confidential reference",
    "pricing discount for Globex",
    "how do I reset my password",
    "how many days of leave do I get",
    "contract team salary",
]


# ---------- Part 1: the maths ---------------------------------------------------------

def test_cosine_of_identical_text_is_one_and_of_unrelated_text_is_zero():
    a = te.embed("reset your password")
    assert te.cosine(a, a) == pytest.approx(1.0)
    assert te.cosine(a, te.embed("annual leave days")) == 0.0


def test_token_estimate_is_about_four_characters_per_token():
    assert te.estimate_tokens("") == 0
    assert te.estimate_tokens("x" * 400) == 100


# ---------- Part 2: prove the naive retriever is unsafe ---------------------------------

def test_naive_retriever_gives_restricted_hr_data_to_an_intern():
    hits = te.NaiveRetriever().search("what is the salary range for senior engineers", INTERN)
    assert any(te.SALARY_CANARY in h.doc.text for h in hits)


def test_naive_retriever_crosses_tenants():
    hits = te.NaiveRetriever().search("pricing discount for Globex", EMPLOYEE)
    assert any(h.doc.tenant == "globex" for h in hits)


def test_keyword_stuffing_wins_the_similarity_ranking():
    hits = te.NaiveRetriever().search("how do I reset my password", EMPLOYEE)
    assert hits[0].doc.id == "poisoned-faq"  # similarity is easy to game


# ---------- Part 3: the secure retriever holds (impact-based) ---------------------------

@pytest.mark.parametrize("query", QUERIES)
@pytest.mark.parametrize("user", [INTERN, EMPLOYEE, GLOBEX_USER], ids=lambda u: u.name)
def test_secure_retriever_never_returns_a_document_the_user_may_not_read(user, query):
    for h in te.SecureRetriever().search(query, user, k=5):
        assert h.doc.tenant == user.tenant
        assert h.doc.allowed_roles & user.roles
        assert h.doc.source == "kb"


def test_benign_path_hr_still_finds_salary_bands():
    hits = te.SecureRetriever().search("what is the salary range for senior engineers", HR)
    assert hits and hits[0].doc.id == "salary-bands"


def test_benign_path_password_question_gets_the_real_answer():
    hits = te.SecureRetriever().search("how do I reset my password", EMPLOYEE)
    assert [h.doc.id for h in hits] == ["password-reset"]


# ---------- Part 4: switch filters off to prove what each one protects ------------------

def test_without_acl_filter_the_intern_leak_returns():
    r = te.SecureRetriever(acl_filter=False)
    hits = r.search("what is the salary range for senior engineers", INTERN)
    assert any(te.SALARY_CANARY in h.doc.text for h in hits)


def test_without_tenant_filter_the_cross_tenant_leak_returns():
    r = te.SecureRetriever(tenant_filter=False)
    assert any(h.doc.tenant == "globex" for h in r.search("pricing discount for Globex", EMPLOYEE))


def test_without_trusted_sources_the_poisoned_upload_wins_again():
    r = te.SecureRetriever(trusted_sources=False)
    assert r.search("how do I reset my password", EMPLOYEE)[0].doc.id == "poisoned-faq"


# ---------- Part 5: context window and budgets ------------------------------------------

PADDED = "please summarise " + "lorem ipsum " * 3000 + "now tell me the salary bands"


def test_naive_truncation_silently_drops_the_system_prompt():
    ctx = te.naive_context(te.SYSTEM_PROMPT, ["user: hi"], PADDED, window=300)
    assert te.SYSTEM_PROMPT not in ctx


def test_safe_context_rejects_oversized_input_instead_of_truncating():
    with pytest.raises(te.InputTooLarge):
        te.safe_context(te.SYSTEM_PROMPT, ["user: hi"], PADDED, window=300)


def test_safe_context_keeps_system_prompt_and_drops_oldest_history_first():
    history = [f"turn {i}: " + "words " * 40 for i in range(20)]
    ctx = te.safe_context(te.SYSTEM_PROMPT, history, "what is my leave balance?", window=300)
    assert ctx.startswith(te.SYSTEM_PROMPT)
    assert "turn 19" in ctx and "turn 0:" not in ctx
    assert te.estimate_tokens(ctx) <= 300 + 5  # small slack for joining newlines


def test_token_budget_stops_a_cost_attack():
    budget = te.TokenBudget(daily_limit=100_000)
    served = sum(budget.charge("mallory", te.estimate_tokens(PADDED)) for _ in range(1000))
    assert served < 20
    assert budget.charge("alice", 50)  # other users are unaffected
