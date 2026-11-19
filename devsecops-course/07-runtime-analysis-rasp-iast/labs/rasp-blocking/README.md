# Lab: RASP protect mode (block a tainted SQL injection) and measure overhead

**Course exercise:** RASP versus IAST. **Lessons:** [01](../../01-what-is-runtime-analysis-iast-and-rasp.md), [02 overhead and false blocks](../../02-challenges-and-cicd-suitability.md#12-performance-overhead).

**Time:** 45 minutes. **Tests:** 8, offline. **Safety:** same toy app as [iast-instrumentation](../iast-instrumentation/README.md) (in-memory sqlite, a stub "shell" that never runs commands, a virtual file system with FAKE content). No network.

## What it does

`protect.py` reuses the IAST agent but runs it with `mode="block"`:

- the agent still tracks taint and finds vulnerable flows;
- at the sink it also asks: does the **tainted part** look hostile (a quote, `;`, `--`, `UNION`, `OR x=`, `..`, `|`, `&`)?
- if yes and the kind is in `block_kinds`, it **raises `AttackBlocked`** before the sink runs; `handle()` turns that into HTTP 403;
- benign tainted input (`alice`) is **allowed**, but the flow is still recorded for developers;
- tainted data in a **bound parameter** is not code, so it is never blocked;
- `block_kinds` lets you block SQL injection and only **monitor** other classes (the roll-out pattern).

`benchmark(n)` times the same benign request with no agent, IAST report mode and RASP block mode.

## Run

```text
.venv/Scripts/python devsecops-course/07-runtime-analysis-rasp-iast/labs/rasp-blocking/demo.py
.venv/Scripts/python -m pytest devsecops-course/07-runtime-analysis-rasp-iast/labs/rasp-blocking -v
```

## Expected output (real run; the timings will differ on your machine)

```text
== NO PROTECTION (report only) ==
  sqli                       -> 200  [(1, 'alice'), (2, 'bob')]
  path traversal             -> 200  root:x:0:0:FAKE-CANARY
  command inj.               -> 200  ok
  benign user                -> 200  [(1, 'alice')]
  safe query, hostile text   -> 200  []
  commands that reached the shell stub: ['ping -c 1 127.0.0.1; cat /etc/passwd']
== PROTECT MODE ==
  sqli                       -> 403  blocked by runtime protection: SQL_INJECTION
  path traversal             -> 403  blocked by runtime protection: PATH_TRAVERSAL
  command inj.               -> 403  blocked by runtime protection: COMMAND_INJECTION
  benign user                -> 200  [(1, 'alice')]
  safe query, hostile text   -> 200  []
  commands that reached the shell stub: []

== monitor-only for command injection (block_kinds = SQL only) ==
   (200, 'ok')
   finding blocked flag: False

== overhead (microseconds per request, toy app, your numbers will differ) ==
  no agent         13.6 us   x1.00
  IAST report      27.6 us   x2.03
  RASP block       24.1 us   x1.77
```

## Reading the overhead

- The toy handler does almost nothing, so the agent's fixed cost looks like a doubling. In a real service, the database and network take milliseconds and the agent adds a small fraction. **The lesson is the method**: measure p50 and p99 with and without the agent, under realistic load.
- The timing test only checks that numbers exist and are sane (a smoke test, not a performance claim).

## Steps

1. Run the demo. Compare the two blocks: which requests changed from 200 to 403?
2. Try `user_by_name` with `O'Brien`. It is blocked: a false positive for a legitimate name when SQL is built by concatenation. What is the proper fix? (A bound parameter: then both the name and the security problem are solved.)
3. Set `block_kinds={"SQL_INJECTION"}` and attack `ping`. Verify the finding says `blocked=False` and the stub recorded the command.
4. Run `benchmark(20000)`. Does the ratio stay stable?
5. Write down a roll-out plan: monitor for a week, review alerts, enable blocking for SQL first, keep a bypass switch.

## Run the real tool

Commercial and open-source RASP products ship the agent with a protect mode and a console: see [lesson 03](../../03-commercial-implementations.md) and the [walkthrough](../commercial-iast-walkthrough.md#9-production-and-rasp-optional). A WAF in front of the app is a complement, not a substitute.
