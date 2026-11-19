"""AST scanner tests: every weakness is found in the vulnerable app, none in the fixed one.

The last test checks YOUR fix in my_fix/app.py (skipped until you change it).

Run from the repository root:
    python -m pytest caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses -v
"""

from pathlib import Path

import pytest

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "scanner")
HERE = Path(__file__).resolve().parent
VULN = HERE / "sample_app" / "vulnerable_app.py"
FIXED = HERE / "sample_app" / "fixed_app.py"
MINE = HERE / "my_fix" / "app.py"


def rules(source: str) -> set[str]:
    return {f.rule for f in s.scan_source(source)}


def test_vulnerable_app_triggers_every_rule():
    assert rules(VULN.read_text(encoding="utf-8")) == set(s.SEVERITY)


def test_each_named_weakness_is_found_on_the_right_line():
    findings = {(f.rule, f.message.split()[0]) for f in s.scan_file(VULN)}
    assert ("AIC001", "pickle.load()") in findings
    assert ("AIC001", "torch.load()") in findings
    assert ("AIC001", "joblib.load()") in findings
    assert ("AIC001", "yaml.load()") in findings
    assert ("AIC006", "trust_remote_code=True") in findings


def test_model_output_into_eval_and_shell_is_the_critical_finding():
    crit = [f for f in s.scan_file(VULN) if f.severity == "CRITICAL"]
    sinks = {f.message.split(" flows into ")[1] for f in crit}
    assert sinks == {"eval()", "subprocess.run()"}


def test_fixed_app_is_clean():
    assert s.scan_file(FIXED) == []


@pytest.mark.parametrize("snippet,expected", [
    ("import pickle\npickle.loads(b)", "AIC001"),
    ("import torch\ntorch.load(p, weights_only=True)", None),
    ("import torch\ntorch.load(p, weights_only=False)", "AIC001"),
    ("import yaml\nyaml.load(t, Loader=yaml.SafeLoader)", None),
    ("import yaml\nyaml.safe_load(t)", None),
    ("import subprocess\nsubprocess.run(['ls'])", None),
    ("import subprocess\nsubprocess.run('ls', shell=True)", "AIC004"),
    ("eval('1+1')", None),
    ("eval(x)", "AIC003"),
    ("API_KEY = 'changeme'", None),
    ("token = os.environ['T']", None),
    ("password = 'correct-horse-battery'", "AIC005"),
    ("m = X.from_pretrained('a', revision='abc123')", None),
])
def test_rule_precision(snippet, expected):
    got = rules(snippet)
    assert got == ({expected} if expected else set()), got


def test_taint_is_per_function_and_needs_a_model_call():
    safe = "def f(llm, q):\n    note = 'hello'\n    eval(note)\n"
    assert "AIC002" not in rules(safe)  # eval of a literal-assigned name is AIC003 territory, not model taint
    tainted = "def f(llm, q):\n    r = llm.complete(q)\n    exec(r)\n"
    assert {"AIC002", "AIC003"} <= rules(tainted)


def test_the_scanner_never_runs_the_code():
    # If it executed this, the NameError would surface; parsing alone is fine.
    assert s.scan_source("undefined_function_that_would_fail()\n") == []


def test_command_line_exit_codes():
    assert s.main([str(VULN)]) == 1
    assert s.main([str(FIXED)]) == 0


def test_learner_fix_is_clean_and_still_defines_the_same_functions():
    text = MINE.read_text(encoding="utf-8")
    if text == VULN.read_text(encoding="utf-8"):
        pytest.skip("exercise not started: fix my_fix/app.py")
    assert s.scan_source(text) == [], [str(f) for f in s.scan_source(text)]
    import ast
    names = {n.name for n in ast.walk(ast.parse(text)) if isinstance(n, ast.FunctionDef)}
    assert {"load_models", "read_config", "fetch", "answer_and_act"} <= names, "keep the functions; fix their insides"
