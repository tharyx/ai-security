# Lab: Automated SQL injection, the sqlmap way (mini version)

**Course exercise:** "Automated SQL Injection Using SQLMAP". Lesson: [02 section 3](../../02-injection-vulnerabilities.md#3-sql-injection) and [section 10](../../02-injection-vulnerabilities.md#10-automated-sql-injection-with-sqlmap). Real tool guide: [real-tools/sqlmap.md](../../real-tools/sqlmap.md).

**Time:** 45 minutes. **Tests:** 6, all offline. **Safety:** the target is a Python function over an in-memory sqlite database. The time-based test uses a virtual clock (`sleep()` is a custom SQL function that only adds numbers), so nothing really waits. The secret is random and labelled FAKE. Only test systems you own or have written permission to test.

## Goal

Understand what sqlmap does under the hood: detect a **blind** injection with boolean and time-based tests, then extract data one character at a time with binary search.

## Concept

The page shows only "In stock" or "Not found": no errors, no data. That is **blind** SQL injection.

1. **Boolean-based (sqlmap technique B):** compare the page for `1 AND 1=1` (same as normal) and `1 AND 1=2` (different). If they differ, the condition is evaluated as SQL.
2. **Time-based (technique T):** `1 AND sleep(5)=0` makes the response 5 seconds slower. (Oracle: `DBMS_SESSION.SLEEP` or heavy queries; MySQL `SLEEP()`; PostgreSQL `pg_sleep()`.)
3. **Extraction:** ask yes/no questions like `unicode(substr((SELECT value FROM secrets),1,1)) > 77`. Binary search needs about 7 requests per ASCII character.

The fix is the same as always: **bind variables** (and here, `int()` on a numeric ID).

## Steps

1. Run the demo and count the extraction requests.
2. Change `extract` to a linear search over printable characters and compare request counts.
3. Make the vulnerable target return the same page for every input but keep the virtual delay. Only the time-based test now detects it: that is why sqlmap has several techniques.

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/mini-sqlmap/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/mini-sqlmap -q -p no:cacheprovider
```

## Expected output (real run)

```text
== Target (string-built SQL) GET /product?id=1 ==
  [B] boolean-based blind: injectable
  [T] time-based blind   : injectable (5s virtual delay)
  dumped secrets.value = FAKEa7e626  (77 requests)

== Target (parameterized) GET /product?id=1 ==
  [B] boolean-based blind: not injectable
  [T] time-based blind   : not injectable
```

## Run the real tool (hedged)

```text
sqlmap -u "https://lab.example/product?id=1" --batch --technique=BT --dbs
sqlmap -r request.txt -p id --batch --level 2 --risk 1 -D shop -T secrets --dump
```

`-r` takes a request saved from Burp. Check `sqlmap --help` for your version. Only against the course lab.

## What you learned

- Blind injection leaks data through a single bit (page A vs page B, fast vs slow).
- Tools automate detection and extraction, but parameterized queries stop all of it.
