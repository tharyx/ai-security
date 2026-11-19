# Lab: Exploiting broken authentication with SQL injection (sqlite3)

**Course item:** "Exploiting Broken Authentication With SQL Injection". **Lesson:** [02 section 7](../../02-authentication-attacks.md#7-exploiting-broken-authentication-with-sql-injection).

**Time:** 30 minutes. **Tests:** 6, offline. **Safety:** an in-memory sqlite3 database with two toy accounts. Only test systems you own or have written permission to test.

## Goal

Log in without a password by injecting into a concatenated SQL query, then show that bound parameters make the same input harmless.

## Files

| File | Role |
|---|---|
| [sqli_login.py](sqli_login.py) | `make_db`, `login_vulnerable` (f-string SQL), `login_secure` (`?` placeholders), payloads `BYPASS_USERNAME`, `BYPASS_ADMIN` |
| [demo.py](demo.py) | runs normal, wrong and injected logins on both |
| [test_aps_ch10_sqli_auth_bypass.py](test_aps_ch10_sqli_auth_bypass.py) | the tests |

## Run

```text
.venv/Scripts/python appsec-course/10-api-authentication/labs/sqli-auth-bypass/demo.py
.venv/Scripts/python -m pytest appsec-course/10-api-authentication/labs/sqli-auth-bypass -q
```

## Real output

```text
=== Vulnerable login (string-concatenated SQL) ===
  valid alice/pw-alice     -> {'username': 'alice', 'role': 'user'}
  wrong password           -> None
  payload "' OR '1'='1' -- " -> {'username': 'alice', 'role': 'user'}
  payload "admin' -- "       -> {'username': 'admin', 'role': 'admin'}

=== Secure login (bound parameters) ===
  valid alice/pw-alice     -> {'username': 'alice', 'role': 'user'}
  payload "' OR '1'='1' -- " -> None
  payload "admin' -- "       -> None
```

## Steps

1. Print the final query string inside `login_vulnerable` for `admin' -- `. Everything after `--` (including the password check) is a comment.
2. Why does `' OR '1'='1' -- ` log in as **alice**? (`fetchone()` returns the first row of an always-true `WHERE`.) Add `ORDER BY role` to the query and see who you become.
3. Try escaping quotes by hand (`username.replace("'", "''")`). It stops these payloads, but explain why bind variables are still the right fix (numeric contexts, other encodings, second-order injection, and the parser never confuses data with code).
4. Note the toy `sha256` password hash. Why is the vulnerable query also a bad design even without injection? (Compare in the application with a slow hash verifier, not in SQL; see the [hash-cracking lab](../password-hash-cracking/README.md).)

## Run the real tool (hedged)

In your course lab, send the payloads through Burp Repeater in the JSON body, then confirm with sqlmap only against the lab target (see [real-tools/auth-testing-tools.md](../../real-tools/auth-testing-tools.md)). Automated detection is built in [chapter 12](../../../12-input-validation-and-injection/README.md).

## What you learned

- Concatenated SQL lets input rewrite the query, including the password check.
- Bound parameters (Oracle bind variables) keep data as data.
- Authentication code needs the same injection hygiene as any other query.
