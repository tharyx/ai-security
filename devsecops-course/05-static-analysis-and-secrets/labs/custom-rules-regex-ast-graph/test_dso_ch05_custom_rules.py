from pathlib import Path

from aisec_lab import load_lab_module

d = load_lab_module(__file__, "detectors")
SRC = (Path(__file__).resolve().parent / "fixtures" / "cases.py").read_text(encoding="utf-8")


def flagged(detector, src=SRC):
    return {h.function for h in d.DETECTORS[detector](src)}


def test_ground_truth_has_seven_vulnerable_and_eight_safe_cases():
    t = d.ground_truth(SRC)
    assert sum(v == "vuln" for v in t.values()) == 7 and sum(v == "safe" for v in t.values()) == 8


def test_all_three_detect_the_obvious_cases():
    for det in d.DETECTORS:
        assert {"case_a_direct_fstring", "case_i_command_line_argument", "case_l_format_on_request_value"} <= flagged(det)


def test_regex_false_positives_on_constants_and_casts():
    f = flagged("regex")
    assert {"case_c_constant_table_name", "case_e_int_cast", "case_j_constant_folding"} <= f


def test_regex_cannot_follow_a_variable_or_a_helper():
    f = flagged("regex")
    assert "case_d_variable_indirection" not in f and "case_g_helper_function" not in f


def test_ast_folds_constants_but_not_data_flow():
    f = flagged("ast")
    assert "case_j_constant_folding" not in f            # "a" + "b" is a literal
    assert "case_d_variable_indirection" not in f        # arg is a Name: structure alone cannot say
    assert "case_n_overwritten_with_constant" in f       # no notion of order of assignment


def test_graph_follows_variables_helpers_and_branches():
    f = flagged("graph")
    assert {"case_d_variable_indirection", "case_g_helper_function", "case_m_json_body", "case_o_one_branch_tainted"} <= f


def test_graph_respects_sanitizer_and_overwrite():
    f = flagged("graph")
    assert "case_e_int_cast" not in f and "case_n_overwritten_with_constant" not in f
    assert "case_c_constant_table_name" not in f and "case_k_tainted_but_unused" not in f


def test_graph_still_has_a_documented_false_positive_for_guards():
    assert "case_h_validated_with_guard" in flagged("graph")      # no path-sensitivity or guard modelling


def test_parameterised_query_is_quiet_everywhere():
    for det in d.DETECTORS:
        assert "case_f_parameterised" not in flagged(det)


def test_precision_improves_regex_then_ast_then_graph():
    p = {k: d.score(SRC, k)["precision"] for k in d.DETECTORS}
    r = {k: d.score(SRC, k)["recall"] for k in d.DETECTORS}
    assert p["regex"] < p["ast"] < p["graph"]
    assert r["regex"] < r["ast"] < r["graph"] == 1.0


def test_taint_path_is_explained_source_to_sink():
    h = next(h for h in d.detect_graph(SRC) if h.function == "case_g_helper_function")
    assert h.why.startswith("source request.form") and "through build_query()" in h.why and h.why.endswith("(line 47)")


def test_sanitizer_list_is_what_decides_safety():
    src = "def f():\n    u = request.args['x']\n    u = escape_sql(u)\n    cur.execute('A' + u)\n"
    assert flagged("graph", src) == set()
    src2 = src.replace("escape_sql", "mystery")
    assert flagged("graph", src2) == {"f"}                 # unknown function: conservative, still tainted
