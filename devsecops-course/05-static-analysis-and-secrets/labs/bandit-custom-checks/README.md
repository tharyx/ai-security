# Lab: Writing custom checks in Bandit for your enterprise applications

**Course exercise:** "Writing custom checks in the bandit for your enterprise applications." Lessons: [03 custom rules](../../03-custom-rules-regex-ast-graph.md), [01 SAST basics](../../01-sast-basics-and-tools.md). Related: [CSE ch2 SAST lab](../../../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sast/README.md), [CMCPSE ch5 SAST lab](../../../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/README.md).

**Time:** 90 minutes. **Tests:** 12, all offline. **Safety:** the "enterprise app" in [fixtures/enterprise_app](fixtures/enterprise_app) is fictional and only **parsed** with `ast`. It is never imported or run. No Bandit install is needed.

## What it does

- [bandit_lite.py](bandit_lite.py) is a small **Bandit-like framework** that copies the shape of Bandit's plugin API: a check is a function receiving a `Context` (`call_function_name_qual` with import aliases resolved, `call_args`, `call_keywords`, `decorators`, `local_assignments()`), declared with `@checks("Call")` and `@test_id("E901")`, returning an `Issue(severity, confidence, cwe, text)`. It supports `# nosec` and `# nosec E904`. It also contains seven simplified built-in checks (B101, B301, B307, B324, B501, B506, B602) and a deliberately **naive B608** (SQL string building) that reproduces a real source of false positives.
- [corp_checks.py](corp_checks.py) has four **enterprise** checks:

| Id | Rule | CWE | False-positive care |
|---|---|---|---|
| E901 | `corpdb.execute()` query built from non-constant input | 89 | Constants, module-level `CONSTANTS` and `int()` casts are fine; follows one local variable |
| E902 | `corp_http` call without `timeout=` | 400 | `**kwargs` calls are skipped |
| E903 | Secret-looking **identifiers** passed to logging | 532 | Words in string literals, `token_count`-style names and `mask()`/`redact()` are ignored |
| E904 | `delete_*`, `admin_*`, `purge_*` function without a role decorator | 862 | Private `_helpers` skipped; `# nosec E904` honoured |

- [evaluate.py](evaluate.py) scores a scanner against **ground truth** written in the fixtures (`# expect: sqli` on def lines) at function level, and builds the **generic baseline** (built-in B608 plus a grep-style rule for secret words near logging).

## Run

```text
.venv/Scripts/python devsecops-course/05-static-analysis-and-secrets/labs/bandit-custom-checks/demo.py
.venv/Scripts/python -m pytest devsecops-course/05-static-analysis-and-secrets/labs/bandit-custom-checks -v
```

## Expected output (real run)

```text
== 1. built-in checks (Bandit-like) on legacy.py
B324 HIGH  /HIGH   CWE-327 line 11  Use of weak hash md5.
B301 MEDIUM/HIGH   CWE-502 line 15  Pickle can run code while loading untrusted data.
B506 MEDIUM/HIGH   CWE-20  line 19  yaml.load without a safe Loader can build arbitrary objects.
B602 HIGH  /HIGH   CWE-78  line 23  subprocess call with shell=True.
B501 HIGH  /HIGH   CWE-295 line 27  Certificate validation is disabled.
B101 LOW   /HIGH   CWE-703 line 31  Use of assert detected; it is removed when Python runs with -O.
B307 MEDIUM/HIGH   CWE-78  line 32  Use of eval() is insecure.

== 2. our four custom checks on the enterprise app
E904 HIGH  /MEDIUM CWE-862 admin.py:10  delete_order() has no role check decorator.
E904 HIGH  /MEDIUM CWE-862 admin.py:14  purge_cache() has no role check decorator.
E901 HIGH  /HIGH   CWE-89  orders.py:17  corpdb query text is built from non-constant input; pass values as parameters.
E901 HIGH  /HIGH   CWE-89  orders.py:21  corpdb query text is built from non-constant input; pass values as parameters.
E901 HIGH  /HIGH   CWE-89  orders.py:35  corpdb query text is built from non-constant input; pass values as parameters.
E903 MEDIUM/HIGH   CWE-532 reports.py:10  'api_token' looks like a secret and is written to the log.
E903 MEDIUM/HIGH   CWE-532 reports.py:23  'password' looks like a secret and is written to the log.
E902 MEDIUM/HIGH   CWE-400 reports.py:31  corp_http call without a timeout can hang a worker forever.

== 3. false positives: generic rules vs custom rules (function-level scoring)
baseline (built-in B608 + grep for secret words)
  authz       TP=0 FP=0 FN=2  precision=1.0  recall=0.0
  secret-log  TP=2 FP=3 FN=0  precision=0.4  recall=1.0
  sqli        TP=3 FP=2 FN=0  precision=0.6  recall=1.0
  timeout     TP=0 FP=0 FN=1  precision=1.0  recall=0.0
  total {'tp': 5, 'fp': 5, 'fn': 3}
custom checks
  authz       TP=2 FP=0 FN=0  precision=1.0  recall=1.0
  secret-log  TP=2 FP=0 FN=0  precision=1.0  recall=1.0
  sqli        TP=3 FP=0 FN=0  precision=1.0  recall=1.0
  timeout     TP=1 FP=0 FN=0  precision=1.0  recall=1.0
  total {'tp': 8, 'fp': 0, 'fn': 0}
```

## Steps

1. Read part 1: the built-in checks find the seven legacy problems in `legacy.py`.
2. Read part 2: the custom checks report eight findings across three files. `delete_cache_entry` is **not** reported because of `# nosec E904` with a reason; `delete_user` has a decorator.
3. Read part 3: the generic baseline finds 5 real issues but also **5 false positives** (constants and `%d` formatting flagged as SQL injection; "password reset" text and `token_count` flagged as secret logging) and **3 misses** (authorization and timeout are invisible to it). The custom rules have 0 false positives and 0 misses on this fixture.
4. Open `orders.py` and add a function with a new unsafe pattern. Add `# expect: sqli` to the def line. Does E901 catch it? If not, extend `dynamic_sql()`.
5. Add a **false-positive trap** of your own (a safe pattern that looks unsafe) and fix the rule without hiding real findings. Re-run the scores.
6. Add a fifth rule (for example "no `print()` of request objects" or "`corp_http` must use `https://`") with a test file of lines that must and must not match.

## Run the real tool: the real Bandit plugin skeleton (hedged)

The real API uses `bandit.core.test_properties` decorators and an **entry point** in the `bandit.plugins` group. The framework here mirrors it so the transition is small. Skeleton and CLI usage are in [real-tools/sast-tools.md](../../real-tools/sast-tools.md#real-bandit-plugin-skeleton-custom-check). **Verify the import paths, Issue fields and entry-point format against the Bandit documentation for your version.** Install Bandit and the plugin into the same virtual environment, then run `bandit -r app -t B901`.

## Limits

- `local_assignments()` is **flow-insensitive** (latest assignment in the function). It is enough for the lab but a real taint engine ([custom-rules-regex-ast-graph](../custom-rules-regex-ast-graph/README.md)) does better.
- Ground truth at **function level** hides multiple findings in one function. Real evaluation uses finer units and many more cases.
