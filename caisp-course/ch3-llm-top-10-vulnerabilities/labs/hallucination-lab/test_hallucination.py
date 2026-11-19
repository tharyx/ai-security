"""Hallucination lab tests: fake citations, fake packages, ungrounded claims, and the checks that catch them.

Run from the repository root:
    python -m pytest caisp-course/ch3-llm-top-10-vulnerabilities/labs/hallucination-lab -v
"""

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "detector")
LIBRARY = d.load_json("library.json")
APPROVED = set(d.load_json("approved_packages.json"))
PASSAGES = ["The gateway limit is 100 requests per minute per API key. Limits reset every minute."]


def test_unknown_doi_and_author_are_flagged_and_real_ones_pass():
    text = "See Lopez et al. (2020) doi 10.5555/lab.001 and Smith et al. (2019) doi 10.5555/lab.999."
    status = {c.text: c.status for c in d.check_citations(text, LIBRARY)}
    assert status["10.5555/lab.001"] == "verified"
    assert status["10.5555/lab.999"] == "unverified"
    assert status["Lopez (2020)"] == "verified"
    assert status["Smith (2019)"] == "unverified"


def test_a_real_author_with_the_wrong_year_is_unverified():
    assert d.check_citations("Lopez (2018) showed", LIBRARY)[0].status == "unverified"


def test_invented_package_is_unknown_and_close_name_is_a_lookalike():
    f = {p.name: p for p in d.check_packages("pip install flask-securejwt-utils\npip install reqeusts", APPROVED)}
    assert f["flask-securejwt-utils"].status in {"unknown", "lookalike"}
    assert f["reqeusts"].status == "lookalike" and f["reqeusts"].suggestion == "requests"


def test_approved_package_and_stdlib_import_pass():
    f = d.check_packages("pip install requests\nimport json", APPROVED)
    assert [p.status for p in f] == ["approved"]


def test_package_names_are_normalised():
    assert d.check_packages("pip install Flask_JWT_Extended", APPROVED)[0].status == "approved"


def test_grounding_flags_the_wrong_number():
    bad = d.check_grounding("The gateway limit is 5000 requests per minute per API key.", PASSAGES)
    good = d.check_grounding("The gateway limit is 100 requests per minute per API key.", PASSAGES)
    assert not bad.grounded and good.grounded


def test_grounding_flags_a_sentence_with_no_source():
    rep = d.check_grounding("Limits reset every minute. The service was built in 1999.", PASSAGES)
    assert rep.supported == ["Limits reset every minute."] and len(rep.unsupported) == 1


def test_model_hallucinates_citations_and_packages_without_sources():
    llm = d.HallucinatingLLM()
    assert "10.5555/lab.999" in llm.complete([{"role": "user", "content": "Please cite a study."}])
    assert "flask-securejwt-utils" in llm.complete([{"role": "user", "content": "Which package should I install?"}])


def test_pipeline_withholds_an_answer_with_an_unapproved_package():
    res = d.answer_with_checks("Which package should I install for JWT?", d.HallucinatingLLM(),
                               library=LIBRARY, approved=APPROVED)
    assert res.status == "blocked" and res.text == "[answer withheld]"


def test_pipeline_marks_fake_citations_for_review():
    res = d.answer_with_checks("Please cite a study on prompt filters.", d.HallucinatingLLM(),
                               library=LIBRARY, approved=APPROVED)
    assert res.status == "needs-review" and "unverified citations" in res.reasons[0]


def test_pipeline_with_rag_is_grounded_and_ok():
    res = d.answer_with_checks("What is the gateway limit?", d.HallucinatingLLM(),
                               library=LIBRARY, approved=APPROVED, passages=PASSAGES)
    assert res.status == "ok", res


def test_without_sources_the_model_states_a_wrong_number_with_confidence():
    # No grounding passages, so the number is invented. Grounding would catch it:
    llm = d.HallucinatingLLM()
    answer = llm.complete([{"role": "user", "content": "What is the limit?"}])
    assert "5000" in answer and not d.check_grounding(answer, PASSAGES).grounded


def test_pipeline_cannot_verify_a_number_without_sources_so_it_asks_for_review():
    res = d.answer_with_checks("How many requests per minute?", d.HallucinatingLLM(),
                               library=LIBRARY, approved=APPROVED)
    assert res.status == "needs-review" and "no source" in res.reasons[0]
