# Lab: Custom rules with regular expressions, AST and graphs (data and control flow)

**Course topic:** "Various approaches to write custom rules in free and paid tools": Regular expressions, Abstract Syntax Trees, Graphs ( Data and Control Flow analysis). Lessons: [03 custom rules](../../03-custom-rules-regex-ast-graph.md). Related: [CSE ch2 SAST lab](../../../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sast/README.md) (a full taint scanner), [bandit-custom-checks](../bandit-custom-checks/README.md).

**Time:** 90 minutes. **Tests:** 12, all offline. **Safety:** [fixtures/cases.py](fixtures/cases.py) is only **parsed**; nothing is imported or executed.

## What it does

[detectors.py](detectors.py) detects **one weakness (SQL injection)** in **15 code shapes** using three detectors, and scores them against `# truth: vuln|safe` labels on the fixture:

| Detector | Method | How |
|---|---|---|
| `detect_regex` | Regular expression | One pattern over each line: an `execute(` followed by an f-string, a string literal followed by `+` or `%`, or `.format(` |
| `detect_ast` | Abstract syntax tree | Finds `.execute()` calls whose first argument is a `BinOp`, f-string or `.format()` call with a non-constant part; folds `"a" + "b"` as constant |
| `detect_graph` | Data and control flow (taint) | Sources (`request.*`, `sys.argv`, `input`), propagation through assignments, concatenation, f-strings and calls, **sanitizers** (`int`, `float`, `escape_sql`), statement order (overwriting kills taint), `if/else` merge, and **one-level function summaries** so `execute(build_query(uid))` is caught. Reports the path |

This is a **teaching model** of what CodeQL and Semgrep taint mode do, not a real engine.

## Run

```text
.venv/Scripts/python devsecops-course/05-static-analysis-and-secrets/labs/custom-rules-regex-ast-graph/demo.py
.venv/Scripts/python -m pytest devsecops-course/05-static-analysis-and-secrets/labs/custom-rules-regex-ast-graph -v
```

## Expected output (real run)

```text
15 cases: 7 vulnerable, 8 safe

case                                 truth  regex  ast    graph
case_a_direct_fstring                vuln   FLAG   FLAG   FLAG 
case_b_constant_query                safe   -      -      -    
case_c_constant_table_name           safe   FLAG   FLAG   -     <regex:FP> <ast:FP>
case_d_variable_indirection          vuln   -      -      FLAG  <regex:FN> <ast:FN>
case_e_int_cast                      safe   FLAG   FLAG   -     <regex:FP> <ast:FP>
case_f_parameterised                 safe   -      -      -    
case_g_helper_function               vuln   -      -      FLAG  <regex:FN> <ast:FN>
case_h_validated_with_guard          safe   FLAG   FLAG   FLAG  <regex:FP> <ast:FP> <graph:FP>
case_i_command_line_argument         vuln   FLAG   FLAG   FLAG 
case_j_constant_folding              safe   FLAG   -      -     <regex:FP>
case_k_tainted_but_unused            safe   -      -      -    
case_l_format_on_request_value       vuln   FLAG   FLAG   FLAG 
case_m_json_body                     vuln   -      FLAG   FLAG  <regex:FN>
case_n_overwritten_with_constant     safe   -      FLAG   -     <ast:FP>
case_o_one_branch_tainted            vuln   -      FLAG   FLAG  <regex:FN>

regex  precision=0.43  recall=0.43  FP=['case_c_constant_table_name', 'case_e_int_cast', 'case_h_validated_with_guard', 'case_j_constant_folding'] FN=['case_d_variable_indirection', 'case_g_helper_function', 'case_m_json_body', 'case_o_one_branch_tainted']
ast    precision=0.56  recall=0.71  FP=['case_c_constant_table_name', 'case_e_int_cast', 'case_h_validated_with_guard', 'case_n_overwritten_with_constant'] FN=['case_d_variable_indirection', 'case_g_helper_function']
graph  precision=0.88  recall=1.0   FP=['case_h_validated_with_guard'] FN=[]

== taint path found by the graph detector for case_g_helper_function
source request.form (line 46) -> uid = ... (line 46) -> through build_query() (line 47) -> sink execute() (line 47)
```

## Steps

1. Read the table row by row. **Case D** (a query built in a variable, then executed) is missed by regex and AST: neither follows the variable. **Case G** (a helper function builds the query) needs function summaries.
2. **Cases C, E and J** are safe code that looks risky. Regex flags all three; the AST folds the constant concatenation (J) but still flags the module constant (C) and the `int()` cast (E). The graph detector knows `int()` is a sanitizer and that `TABLE` is not tainted.
3. **Case N** overwrites a tainted variable with a constant. Only the graph detector, which respects statement order, stays quiet.
4. **Case H** (`if not uid.isdigit(): abort()`) fools **all three**. The graph detector has no path-sensitive reasoning. Real tools model validation guards or ask you to add a sanitizer rule. No method is perfect.
5. Look at the taint path printed for case G. This is what a developer needs in the finding to understand it.
6. Add your own case (for example `os.system` with a tainted command, or a `%` format with a tuple) and a truth label. Which detector copes? Add `shlex.quote` to `SANITIZERS` and a command-injection sink to extend the graph detector.

## Precision and recall (from this fixture)

| Detector | Precision | Recall |
|---|---|---|
| regex | 0.43 | 0.43 |
| ast | 0.56 | 0.71 |
| graph | 0.88 | 1.00 |

A **trend, not a benchmark**: 15 hand-picked cases.

## Run the real tool (hedged, verify at source)

The same rule as a **Semgrep** pattern and as a **Semgrep taint-mode** rule is in [real-tools/semgrep-codeql.md](../../real-tools/semgrep-codeql.md), with CodeQL notes. A real Bandit plugin skeleton is in [real-tools/sast-tools.md](../../real-tools/sast-tools.md). Use them on your own code only.
