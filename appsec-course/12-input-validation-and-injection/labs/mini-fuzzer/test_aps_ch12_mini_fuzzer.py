from aisec_lab import load_lab_module

f = load_lab_module(__file__, "fuzzer")


def test_fuzzer_finds_all_three_planted_bugs_in_vulnerable_api():
    found = f.fuzz(secure=False)
    assert {"server error", "stack trace leaked", "unencoded reflection", "negative total accepted"} <= set(found)


def test_fuzzer_finds_nothing_in_validated_api():
    assert f.fuzz(secure=True) == {}


def test_fuzzing_is_reproducible_with_a_seed():
    assert f.fuzz(False, seed=7) == f.fuzz(False, seed=7)


def test_keyword_runner_discovers_hidden_paths_and_filters_404():
    words = {w for w, _, _ in f.fuzz_keyword("/api/v1/FUZZ", f.WORDLIST)}
    assert words == {"orders", "health", "internal/debug", "backup"}


def test_filter_codes_can_hide_more_statuses():
    hits = f.fuzz_keyword("/api/v1/FUZZ", f.WORDLIST, filter_codes=(404, 200))
    assert {w for w, _, _ in hits} == {"orders"}  # GET /orders without body still answers 201


def test_oracle_flags_negative_total():
    assert "negative total accepted" in f.oracle(201, "total -500", -2)
