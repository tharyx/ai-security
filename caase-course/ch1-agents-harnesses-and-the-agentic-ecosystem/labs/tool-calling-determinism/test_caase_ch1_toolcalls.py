from aisec_lab import load_lab_module

tc = load_lab_module(__file__, "toolcalls")
MODELS = [tc.SteadyModel(), tc.FlakyModel()]
N = 40


def test_validator_is_strict():
    ok = {"tool": "get_weather", "args": {"city": "Paris", "units": "c"}}
    assert tc.validate(ok)[0]
    assert not tc.validate({"tool": "get_weather", "args": {"city": "Paris", "units": "celsius"}})[0]
    assert not tc.validate({"tool": "get_weather", "args": {"location": "Paris", "units": "c"}})[0]
    assert not tc.validate({"tool": "get_weather", "args": {"city": "Paris", "units": "c", "x": 1}})[0]
    assert not tc.validate({"tool": "add", "args": {"a": "17", "b": 25}})[0]
    assert not tc.validate({"tool": "add", "args": {"a": True, "b": 25}})[0]
    assert not tc.validate({"tool": "drop_db", "args": {}})[0]
    assert not tc.validate(None)[0]


def test_steady_model_is_perfectly_consistent_even_with_a_fence_around_the_json():
    rep = tc.summarize(tc.run_all([tc.SteadyModel()], tc.TASKS, N, "raw"))["steady-7b"]
    assert rep["parse_valid"] == rep["schema_valid"] == rep["correct"] == rep["consistency"] == 1.0


def test_flaky_model_is_measurably_worse_in_raw_mode():
    rep = tc.summarize(tc.run_all(MODELS, tc.TASKS, N, "raw"))
    steady, flaky = rep["steady-7b"], rep["flaky-3b"]
    assert flaky["parse_valid"] < 1.0           # some replies are not even JSON
    assert flaky["schema_valid"] < flaky["parse_valid"]  # parsing is not conformance
    assert flaky["schema_valid"] < steady["schema_valid"]
    assert flaky["consistency"] < steady["consistency"]


def test_concurrent_and_sequential_runs_give_identical_results():
    a = tc.run_all(MODELS, tc.TASKS, N, "raw", concurrent=True)
    b = tc.run_all(MODELS, tc.TASKS, N, "raw", concurrent=False)
    assert a == b
    assert a == tc.run_all(MODELS, tc.TASKS, N, "raw", concurrent=True)  # repeatable


def test_retry_with_validation_raises_schema_conformance_at_a_cost():
    raw = tc.summarize(tc.run_all(MODELS, tc.TASKS, N, "raw"))["flaky-3b"]
    retry = tc.summarize(tc.run_all(MODELS, tc.TASKS, N, "retry"))["flaky-3b"]
    assert retry["schema_valid"] > raw["schema_valid"]
    assert retry["avg_attempts"] > 1.0


def test_constrained_decoding_guarantees_shape_but_not_truth():
    rep = tc.summarize(tc.run_all(MODELS, tc.TASKS, N, "constrained"))["flaky-3b"]
    assert rep["schema_valid"] == 1.0
    # shape is guaranteed; the values (for example a forced enum member) can still be wrong
    outs = tc.run_all([tc.FlakyModel()], tc.TASKS, N, "constrained")
    assert all(o.schema_ok for o in outs)
    assert rep["correct"] <= rep["schema_valid"]


def test_schema_valid_is_not_the_same_as_safe_or_correct():
    # A call can pass the schema and still be the wrong call (wrong city); policy must check meaning.
    wrong = {"tool": "get_weather", "args": {"city": "Mordor", "units": "c"}}
    assert tc.validate(wrong)[0]
    assert wrong != {"tool": "get_weather", "args": {"city": "Paris", "units": "c"}}


def test_every_quirk_is_reachable():
    seen = set()
    for run in range(200):
        text = tc.FlakyModel().generate(tc.TASKS[0], run)
        if tc.validate(tc.strict_parse(text))[0]:
            seen.add("valid")
        elif tc.strict_parse(text) is None:
            seen.add("unparseable")
        else:
            seen.add("parsed-but-invalid")
    assert seen == {"valid", "unparseable", "parsed-but-invalid"}
