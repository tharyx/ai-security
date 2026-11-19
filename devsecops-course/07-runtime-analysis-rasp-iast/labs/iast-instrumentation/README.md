# Lab: A pure-Python IAST agent

**Course exercise:** runtime analysis with IAST (the offline twin of "a commercial implementation of the IAST tool"; the real walkthrough is [commercial-iast-walkthrough.md](../commercial-iast-walkthrough.md)). **Lessons:** [01 RASP versus IAST](../../01-what-is-runtime-analysis-iast-and-rasp.md), [02 challenges](../../02-challenges-and-cicd-suitability.md).

**Time:** 60 minutes. **Tests:** 10, offline. **Safety:** no network, no real shell (the "shell" is a stub that records the command), a virtual file system with FAKE content, in-memory sqlite.

## What it builds

| File | Role |
|---|---|
| `taint.py` | `TaintedStr`: a `str` that remembers which parts came from the request and records propagation steps (`+`, `%s`, `strip`, `lower`). `sanitize_int` removes taint. Known gap: f-strings and `.format` drop taint. |
| `tinyapp.py` | a tiny backend with 3 sinks (`Database.execute`, `Shell.run`, `Files.open_file`) and handlers. 3 handlers are vulnerable (string concatenation), 1 is safe (bound parameter), 1 is a false-negative trap (f-string). `Request` turns every parameter into a tainted source. |
| `agent.py` | `IastAgent`: **monkey-patches** the sinks, checks whether the code-like argument contains tainted text, and builds the trace SOURCE, PROPAGATE, SINK with file:function:line. `mode="report"` only reports. |
| `qa_suite.py` | the app's ordinary functional tests (no attack payloads). `CURRENT_SUITE` lacks a test for `read_doc`; `FULL_SUITE` adds it. |

## Run

```text
.venv/Scripts/python devsecops-course/07-runtime-analysis-rasp-iast/labs/iast-instrumentation/demo.py
.venv/Scripts/python -m pytest devsecops-course/07-runtime-analysis-rasp-iast/labs/iast-instrumentation -v
```

## Expected output (real run, abridged)

```text
== current nightly suite: 3 functional tests, 3 sink calls, 2 vulnerable flow(s) ==
[SQL_INJECTION] during test_find_user_by_name  (sink value, no attack payload in the test data: "SELECT id, name FROM users WHERE name = 'alice'")
    SOURCE   request.args['name']
    PROPAGATE concat at tinyapp.py:user_by_name:65
    PROPAGATE concat at tinyapp.py:user_by_name:65
    SINK     Database.execute called at tinyapp.py:user_by_name:66
[COMMAND_INJECTION] during test_ping_localhost  (sink value, no attack payload in the test data: 'ping -c 1 127.0.0.1')
    SOURCE   request.args['host']
    PROPAGATE concat at tinyapp.py:ping:69
    SINK     Shell.run called at tinyapp.py:ping:69

== suite + test_read_doc: 4 functional tests, 4 sink calls, 3 vulnerable flow(s) ==
...
[PATH_TRAVERSAL] during test_read_doc  (sink value, no attack payload in the test data: '/srv/docs/readme.txt')
    SOURCE   request.args['file']
    PROPAGATE concat at tinyapp.py:read_doc:72
    SINK     Files.open_file called at tinyapp.py:read_doc:72

== known gap: f-string drops the taint ==
flows reported: 0 (the SQL is built unsafely, but the toy agent cannot see it)
```

Notes: `test_find_user_by_id` (bound parameter) produces **no** finding: the tainted value goes in `params`, not in the SQL text. The line numbers in your run may differ if you edit `tinyapp.py`.

## What to notice

1. **No attack was sent**, yet two vulnerable flows were found. IAST reports the unsafe *construction*.
2. **Coverage depends on tests:** the path-traversal flow appears only when a test calls `read_doc`.
3. **False negative:** the f-string handler is vulnerable but unseen. Real agents hook deeper to reduce such gaps, but gaps remain.
4. **Report mode never blocks:** an actual injection payload still works (a test proves it). Blocking is the next lab.

## Steps

1. Run the demo. Open `tinyapp.py` and match each trace line number to the code.
2. Add a new vulnerable handler and a functional test for it. Does the agent find it with no agent changes? Remove the test: does the finding vanish?
3. Fix `user_by_name` with a bound parameter. What happens to the finding?
4. Make `user_by_name_fstring` visible: change it to concatenation, then think how a real agent could track f-strings.
5. Add `sanitize_int` to `user_by_id` input. Why does the flow stop being tainted?

## Run the real tool

Not available offline: see [commercial-iast-walkthrough.md](../commercial-iast-walkthrough.md). In real agents the "monkey-patching" is done by bytecode instrumentation (Java and .NET) or runtime hooks (Node, Python, Ruby).
