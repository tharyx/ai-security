# Lab: Reviewing code for SQL injection and fixing it with parameterized queries

**Course exercise:** Reviewing code for SQL Injection and Fixing with Parameterized queries. Lesson: [02 section 7](../../02-reviewing-code-for-security-defences.md#7-reviewing-for-sql-injection-and-fixing-with-parameterized-queries).

**Time:** 45 minutes. **Tests:** 9, all offline. **Safety:** in-memory sqlite with toy data. Only test systems you own or have written permission to test.

## Goal

Review four data-access functions, prove each injection, and fix each with the right technique: bind parameters for values, an allowlist for identifiers, generated placeholders for IN lists.

## Concept

[repo.py](repo.py):

| Function | Bug | Fix |
|---|---|---|
| `search_vuln` / `search_fixed` | `LIKE '%" + name + "%'` | `LIKE ?` with `f"%{name}%"` as the bound value |
| `login_vuln` / `login_fixed` | f-string `WHERE username = '{u}' AND password_hash = '...'` | named bind `:u`, hash compared in code with `hmac.compare_digest` |
| `list_sorted_vuln` / `list_sorted_fixed` | `ORDER BY {sort}` from the request | identifiers cannot be bound: map `name`, `price`, `-price` to fixed SQL |
| `by_ids_vuln` / `by_ids_fixed` | `IN ({ids_csv})` | `int()` each id, one `?` per id, size limit |

`order_by_oracle()` shows a **blind** technique: `ORDER BY (CASE WHEN <condition> THEN name ELSE price END)` returns rows in a different order when the condition is true, leaking one bit per request without any error message.

## Run

```text
.venv/Scripts/python appsec-course/02-secure-code-review-and-asvs/labs/sqli-review-and-fix/demo.py
.venv/Scripts/python -m pytest appsec-course/02-secure-code-review-and-asvs/labs/sqli-review-and-fix -q -p no:cacheprovider
```

## Expected output (real run)

```text
1. search, UNION payload
   vuln : ['admin', 'alice']
   fixed: []
   fixed, normal input 'jam': [('Cherry jam', 4.0)]

2. login as admin'-- with a wrong password
   vuln : (2, 'admin')
   fixed: None
   fixed, right password: (1, 'customer')

3. ORDER BY used as a yes/no oracle (is admin's hash first char < '8'?)
   vuln, condition 1=1   : ['Apple juice', 'Banana bread', 'Cherry jam']
   vuln, condition 1=0   : ['Apple juice', 'Cherry jam', 'Banana bread']
   vuln, probe hash char : ['Apple juice', 'Cherry jam', 'Banana bread']
   fixed: unsupported sort key
   fixed, sort=-price    : ['Banana bread', 'Cherry jam', 'Apple juice']

4. IN list with '1) OR (1=1'
   vuln : ['Apple juice', 'Banana bread', 'Cherry jam', 'Staff-only sample']
   fixed: rejected: invalid literal for int() with base 10: '1) OR (1=1'
   fixed, '1,3': ['Apple juice', 'Cherry jam']
```

## Steps

1. Review `repo.py` as if it were a pull request. Write one review comment per vulnerable function: location, risk, fix.
2. Run the demo. In part 3, the probe asks whether the first character of admin's hash is below `'8'`. Explain how repeating such probes extracts the whole hash (this is what sqlmap automates).
3. Note that `search_vuln("O'Reilly")` **crashes**. A 500 on a single quote is how testers first notice SQL injection.
4. Run the same file through the [code-review-checklist reviewer](../code-review-checklist/README.md): `reviewer.py appsec-course/02-secure-code-review-and-asvs/labs/sqli-review-and-fix`. Which functions does `SQL001` flag? It flags all four vulnerable functions, and also `list_sorted_fixed` and `by_ids_fixed`, whose f-strings only insert allowlisted SQL or `?` placeholders. Those are **false positives**: decide how you would mark them (an inline suppression comment with a reason) so the next reviewer does not re-check them.
5. Write the Oracle PL/SQL equivalent of `search_fixed` using `EXECUTE IMMEDIATE ... USING`, and of `list_sorted_fixed` using a `CASE` on an allowlist (or `DBMS_ASSERT`).

## Run the real tool (hedged)

- **sqlmap** confirms injection automatically, only against your own lab target (verify flags): `sqlmap -u "http://127.0.0.1:5000/search?q=jam" --batch --risk 1 --level 2`. Chapter 12 builds a mini sqlmap-style detector.
- **Semgrep / CodeQL / Bandit** find string-built SQL in code: see [real-tools/code-review-tools.md](../../real-tools/code-review-tools.md).

## What you learned

- Data values go in bind parameters; the SQL text is constant. The `%` wildcard belongs to the value.
- Identifiers (columns, sort direction, table names) cannot be bound; map user choices to fixed SQL fragments.
- IN lists need one placeholder per value.
- Blind injection needs no error message; an ordering difference is enough.
- The database account's privileges limit the damage of anything you missed.
