# Real tools: Code review tools and ASVS exports (hedged guide)

> **Hedged guide.** Commands, rule sets and licences change. Verify every command against the tool's current documentation. Nothing in this repo's tests needs these tools. Run them only on code you own or are authorised to review, and do not upload confidential code to services your organisation has not approved. Only test systems you own or have written permission to test.

## Semgrep / Opengrep

```text
pip install semgrep                       # or install Opengrep (the 2025 community fork); verify
semgrep scan --config p/python --config p/owasp-top-ten path/to/code
semgrep scan --config my-rules.yml --sarif -o semgrep.sarif path/to/code
```

A rule equivalent to the lab's `SQL001` (sketch; verify syntax):

```yaml
rules:
  - id: sql-built-from-strings
    languages: [python]
    severity: ERROR
    message: SQL built from strings reaches execute(); use bind parameters
    pattern-either:
      - pattern: $DB.execute(f"...", ...)
      - pattern: $DB.execute("..." + $X, ...)
      - pattern: |
          $Q = "..." + $X
          ...
          $DB.execute($Q, ...)
```

Semgrep's community rules and some features changed licence in 2024 and 2025; check what your organisation may use.

## CodeQL

Free for public repositories on GitHub and for research; licensed for private use (verify). In GitHub: enable code scanning with the default setup. Locally (verify): `codeql database create db --language=python --source-root .` then `codeql database analyze db codeql/python-queries --format=sarif-latest --output=codeql.sarif`.

## Bandit (Python)

```text
pip install bandit
bandit -r path/to/code -f txt
```

Flags `hashlib.md5`, `shell=True`, `verify=False`, hard-coded passwords, `debug=True` and more. Compare its output with the lab's reviewer on `fixtures/vulnerable`.

## Other tools

- SonarQube (server) and SonarQube for IDE (formerly SonarLint).
- Brakeman (Rails), SpotBugs + Find Security Bugs (Java), gosec (Go), eslint-plugin-security and eslint-plugin-no-unsanitized (JavaScript).
- Secrets: Gitleaks, TruffleHog. Dependencies: pip-audit, npm audit, osv-scanner, Trivy.

## ASVS machine-readable files

The OWASP ASVS GitHub repository publishes the standard and, for released versions, CSV/JSON exports (verify the current location and column names). To use one with the lab:

```python
import asvs_checklist as ac
cols = {"ref": "<id column>", "chapter": "<chapter id column>", "chapter_name": "<chapter name column>",
        "text": "<description column>", "level": "<level column>"}
reqs = ac.load_csv("asvs-5.0.0.csv", cols)
```

If the export marks levels as separate L1/L2/L3 columns instead of one level column, add a small conversion step that picks the lowest level marked.

See also: [DevSecOps Semgrep and CodeQL notes](../../../devsecops-course/05-static-analysis-and-secrets/real-tools/semgrep-codeql.md), [DevSecOps SAST tools](../../../devsecops-course/05-static-analysis-and-secrets/real-tools/sast-tools.md).
