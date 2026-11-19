# Real tools: BDD security tests and ASVS

> **Hedged guide.** Verify package names, versions and flags at source. Run security tests only against systems you own or have written permission to test; use `localhost` or a test environment.

## BDD-Security and Gauntlt (legacy)

- **BDD-Security** (Continuum Security, later part of IriusRisk) was the tool behind the course's "BDD security" lab. It appears unmaintained since about 2022 (verify). Learn the idea; do not start new work on it.
- **Gauntlt** ran attack tools (nmap, sqlmap) from Gherkin files. It is also old.

## Current options

| Option | Language | Notes |
|---|---|---|
| **pytest-bdd** | Python | Gherkin feature files with pytest step functions. Good if your tests are already pytest. |
| **behave** | Python | Stand-alone Gherkin runner. |
| **Cucumber** | Java, JavaScript, Ruby | The reference Gherkin implementation. |
| **ZAP Automation Framework** | YAML plans | Drive ZAP (ZAP by Checkmarx) scans and assert on alerts; fits the DAST chapter. |

A pytest-bdd step (sketch, check the docs for your version):

```python
from pytest_bdd import given, when, then, scenarios, parsers

scenarios("features/authentication.feature")

@when(parsers.parse('I submit a wrong password {n:d} times for "{user}"'))
def wrong_password(client, ctx, n, user):
    for _ in range(n):
        ctx["resp"] = client.post("/login", data={"user": user, "password": "wrong"})

@then(parsers.parse("the response status is {code:d}"))
def status(ctx, code):
    assert ctx["resp"].status_code == code
```

Point the client at a local or staging instance (`http://127.0.0.1:8000`), never at production.

## ASVS

- The OWASP ASVS (version 5.0 released May 2025, verify) is published as PDF, Markdown, CSV and JSON on the OWASP project page and GitHub repository. The machine-readable files are the easiest way to import requirement ids and text into your catalog.
- Keep your own stable ids and store the ASVS reference as a field, because numbering changed between 4.x and 5.0.
- Related OWASP material: Proactive Controls, MASVS (mobile), Cheat Sheet Series.

## Linking requirements to tests

Put the requirement id in the test name or tag (`@REQ-AUTH-01`). A small script can then check that every requirement id appears in at least one passing test report, which is exactly what the [requirements lab](../labs/security-requirements-as-code/README.md) gate does with a registry.
