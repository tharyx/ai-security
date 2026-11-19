# Lab: Using Brakeman/Bandit to scan a Ruby on Rails and a Python code base

**Course exercise:** "using brakeman/bandit to scan Ruby on Rails and Python Code Base." Lessons: [01 SAST basics and tools](../../01-sast-basics-and-tools.md#3-tools-by-language). Related: [bandit-custom-checks](../bandit-custom-checks/README.md) (the framework used here).

**Time:** 60 minutes. **Tests:** 9, all offline. **Safety:** the Brakeman report is a **fixture** for a fictional Rails app; Ruby is not needed. The Python fixture is only **parsed**, never run.

## What it does

[brakeman_bandit.py](brakeman_bandit.py) turns two tools' very different outputs into one schema so a pipeline can handle them together:

| Field | Brakeman (JSON `warnings[]`) | Bandit-like (`Issue`) |
|---|---|---|
| tool, language | `brakeman`, `ruby` | `bandit-like`, `python` |
| rule | `check_name` | test id (B602...) |
| CWE | mapped from `warning_type` (SQL Injection to 89, XSS to 79, Command Injection to 78, Redirect to 601, Mass Assignment to 915, File Access to 22; hedged table) | `cwe` on the issue |
| severity | **Brakeman has none**: derived from the CWE by a policy table | from the check |
| confidence | High / Medium / **Weak** mapped to HIGH / MEDIUM / LOW | from the check |
| fingerprint | line-independent hash of type, file, class and method | hash of id, file and code line |

Then: a **score** (severity x confidence, 1 to 9), a merged and de-duplicated list, grouping **by CWE across languages**, and a gate on score with an optional **baseline** of accepted fingerprints. The Bandit-like run uses the `bandit_lite` framework from [bandit-custom-checks](../bandit-custom-checks/bandit_lite.py) (without its naive B608).

## Run

```text
.venv/Scripts/python devsecops-course/05-static-analysis-and-secrets/labs/brakeman-bandit/demo.py
.venv/Scripts/python -m pytest devsecops-course/05-static-analysis-and-secrets/labs/brakeman-bandit -v
```

## Expected output (real run)

```text
brakeman: 6 warnings (1 already ignored in the report); bandit-like: 4 issues

== one list, worst first (score = severity x confidence)
score 9  HIGH  /HIGH   bandit-like B324               CWE-327  api.py:13  Use of weak hash md5
score 9  HIGH  /HIGH   bandit-like B602               CWE-78   api.py:17  subprocess call with shell=True
score 9  HIGH  /HIGH   brakeman    SQL                CWE-89   app/controllers/users_controller.rb:14  SQL Injection
score 6  MEDIUM/HIGH   bandit-like B506               CWE-20   api.py:9  yaml.load without a safe Loader can build arbitrary objects
score 6  HIGH  /MEDIUM brakeman    Execute            CWE-78   app/models/exporter.rb:22  Command Injection
score 6  MEDIUM/HIGH   brakeman    CrossSiteScripting CWE-79   app/views/users/show.html.erb:7  Cross-Site Scripting
score 4  MEDIUM/MEDIUM brakeman    FileAccess         CWE-22   app/controllers/downloads_controller.rb:9  File Access
score 3  LOW   /HIGH   bandit-like B101               CWE-703  api.py:25  Use of assert detected; it is removed when Python runs with -O
score 3  LOW   /HIGH   brakeman    Redirect           CWE-601  app/controllers/sessions_controller.rb:31  Redirect
score 2  MEDIUM/LOW    brakeman    MassAssignment     CWE-915  app/controllers/orders_controller.rb:40  Mass Assignment

== grouped by CWE across both languages
CWE-20: bandit-like:api.py
CWE-22: brakeman:app/controllers/downloads_controller.rb
CWE-327: bandit-like:api.py
CWE-601: brakeman:app/controllers/sessions_controller.rb
CWE-703: bandit-like:api.py
CWE-78: bandit-like:api.py, brakeman:app/models/exporter.rb
CWE-79: brakeman:app/views/users/show.html.erb
CWE-89: brakeman:app/controllers/users_controller.rb
CWE-915: brakeman:app/controllers/orders_controller.rb

== gates
fail on score >= 6          -> exit 1
same gate with all current findings baselined -> exit 0
```

## Steps

1. Look at the merged list. SQL injection from Rails and `shell=True` and `md5` from Python all score 9; "Mass Assignment (Weak)" scores 2.
2. Command injection (CWE-78) appears in **both** languages in the CWE grouping. This is how you report on a weakness class across a polyglot estate.
3. `subprocess.run([...], shell=False)` in the Python fixture is **not** reported: the check looks at `shell=True`.
4. The `ignored_warnings` block in the Brakeman JSON is what `brakeman.ignore` produces. Notice the fingerprint and the note. Find the matching idea in the Bandit world (`# nosec` and baselines).
5. The gate passes when all current findings are in the **baseline**. Think about how baselines can hide risk, and how an expiry date helps.
6. Change `SEVERITY_BY_CWE` so that open redirect counts as `MEDIUM` and see the order and gate change. Policy is a choice you should write down.

## Limits

- Brakeman's CWE mapping here is a small hedged table. Real Brakeman warnings also carry a `warning_code` and links; check the docs.
- The Python side is a simplified Bandit-like engine, not Bandit itself.

## Run the real tools (hedged, verify at source)

```text
brakeman -q -f json -o brakeman.json
bandit -r app -f json -o bandit.json
```

See [real-tools/sast-tools.md](../../real-tools/sast-tools.md). Run them only on your own code. Brakeman needs Ruby; Bandit needs Python.
