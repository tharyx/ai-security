# Lab: Injection playground (SQL, ORM, NoSQL injection and SSRF)

**Course topics:** "SQL Injection", "ORM Injection", "NoSQL Injection", "Server Side Request Forgery", "Prepared Statements". Lesson: [02 Injection vulnerabilities](../../02-injection-vulnerabilities.md).

**Time:** 75 minutes. **Tests:** 9, all offline. **Safety:** `sqlite3` in memory, a mini Mongo-style matcher and a FAKE network (a Python dict). The "admin password" and "cloud credential" are random values labelled FAKE. Only test systems you own or have written permission to test.

## Goal

Exploit four injection classes in toy code, then show the one-line change that makes each attack fail.

## Concept

| Class | Vulnerable code | Fix |
|---|---|---|
| SQL injection | `f"... LIKE '%{term}%'"` | bind variables: `LIKE ?` with a parameter (Oracle: `:term`) |
| ORM injection | `order_by(user_text)` pasted into SQL | allowlist column names; never pass raw SQL fragments |
| NoSQL injection | `{"password": body["password"]}` where the body may be `{"$ne": ""}` | type checks (must be a string), reject `$` keys, schema validation |
| SSRF | server fetches any URL the user gives | allowlist hosts, resolve and block internal IPs, https only, no redirects |

The ORM attack is the interesting one: `ORDER BY` cannot return data, but **the order itself is an oracle**. The lab recovers the admin password one character at a time from whether "pen" sorts first.

## Steps

1. Run the demo and read the four blocks.
2. In [injection_lab.py](injection_lab.py), change `search_safe` to build the `LIKE` pattern with an f-string and run the tests: the SQLi tests now fail, proving they test the fix.
3. Try a stacked query `'; DELETE FROM products; --` against `search_vuln`. sqlite's `execute` refuses multiple statements; Oracle does not allow them in one call either. Why is UNION still enough?
4. Add `$where` support to `_match` (do not!). Explain why server-side JavaScript in a database query is the NoSQL equivalent of `EXECUTE IMMEDIATE` with user input.
5. Add the IPv6 metadata address `http://[fd00:ec2::254]/` to the SSRF tests. Does `preview_safe` block it?

## Run

```text
.venv/Scripts/python appsec-course/12-input-validation-and-injection/labs/injection-playground/demo.py
.venv/Scripts/python -m pytest appsec-course/12-input-validation-and-injection/labs/injection-playground -q -p no:cacheprovider
```

## Expected output (real run)

The FAKE values change on every run.

```text
== SQL injection ==
term='bo'
   vulnerable: [('book', 250.0)]
   bind vars : [('book', 250.0)]
term="' OR hidden = 1 --"
   vulnerable: [('pen', 10.0), ('book', 250.0), ('lamp', 900.0), ('unreleased-phone', 99999.0)]
   bind vars : []
term="' UNION SELECT name, password FROM users --"
   vulnerable: [('admin', 'FAKE-5fbfb952'), ('book', 250.0), ('lamp', 900.0), ('pen', 10.0)]
   bind vars : []

== ORM injection through order_by ==
normal sort -price : ['lamp', 'book', 'pen']
vulnerable ORM: admin password recovered via sort-order oracle -> FAKE-5fbfb952
secure ORM: invalid sort field '(CASE WHEN 1=1 THEN price END)'

== NoSQL operator injection ==
vulnerable login with {'username': 'admin', 'password': {'$ne': ''}} -> admin
secure login -> username and password must be strings

== SSRF via a link-preview feature (FAKE network) ==
https://images.partner.example/cat.png
   vulnerable: <img data>
   secure    : <img data>
http://169.254.169.254/latest/meta-data/
   vulnerable: iam/security-credentials/app-role: FAKE-IAM-CREDENTIAL-71964a58
   secure    : blocked (only https)
https://metadata.attacker.example/
   vulnerable: iam/security-credentials/app-role: FAKE-IAM-CREDENTIAL-71964a58
   secure    : blocked (host not in allowlist)
http://2852039166/
   vulnerable: iam/security-credentials/app-role: FAKE-IAM-CREDENTIAL-71964a58
   secure    : blocked (only https)
```

## Run the real tool (hedged)

- **sqlmap** against the course lab only: see the [mini-sqlmap lab](../mini-sqlmap/README.md) and [real-tools/sqlmap.md](../../real-tools/sqlmap.md).
- **NoSQL:** in Burp Repeater change `"password":"x"` to `"password":{"$ne":null}` on a JSON login. Tools such as **nosqlmap** exist but are old (check maintenance).
- **SSRF:** Burp Collaborator (Professional) or a self-hosted interactsh server shows out-of-band callbacks. Cloud defence: **IMDSv2** (session token required) on AWS.

## What you learned

- Every injection is "data became code". The fix is always to keep data and code in separate channels.
- ORMs are safe only while you stay inside their parameterized API.
- SSRF defence must check the **resolved IP**, not just the host string.
