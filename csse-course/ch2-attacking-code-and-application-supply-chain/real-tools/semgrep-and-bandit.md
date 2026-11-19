# Semgrep and Bandit: real SAST on a small project

> **Status: hedged outline, not tested by the repo author.** Verify commands at <https://semgrep.dev/docs/> and <https://bandit.readthedocs.io/>. Semgrep's licensing and the Opengrep fork changed in 2024-2025: check which engine and rules you may use.

**Offline twin (tested):** [sast](../labs/sast/README.md). Related: [CMCPSE sast-vulnerable-mcp-server](../../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/README.md), which includes Semgrep-style rules.

## Run them on the lab fixtures

Use the lab's fixture as a safe target (it is only parsed, never run):

```text
pip install bandit semgrep          # in a virtual environment; semgrep is a large install
bandit -r csse-course/ch2-attacking-code-and-application-supply-chain/labs/sast/fixtures
semgrep scan --config p/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/sast/fixtures
```

(`p/python` is a registry ruleset name; check current names. Some Semgrep commands may ask you to log in; the local-rules mode works offline: `--config path/to/rules.yml`.)

## Compare with the lab

1. Which of the lab's 12 rules does Bandit cover? (Bandit's test IDs map to many of them, for example `B602` shell, `B608` SQL string building, `B303` weak hash, `B506` yaml load; verify IDs.)
2. Which findings does Semgrep add or miss? Note the **taint mode** in Semgrep rules.
3. Write one custom Semgrep rule for a pattern the lab flags (for example `os.system(...)`) and one **false positive** you suppress with a reason.

## A tiny Semgrep rule (shape; verify the syntax)

```yaml
rules:
  - id: no-os-system
    languages: [python]
    message: os.system with a dynamic string; use subprocess with a list
    severity: ERROR
    pattern: os.system($X)
```

## Practices

- Gate CI on **new** findings (baseline the old ones).
- Keep suppressions with a reason; review them.
- Run a fast ruleset in pre-commit and the full set in CI ([sca-sast-pre-commit](../labs/sca-sast-pre-commit/README.md)).
- Pin tool versions and rulesets (a ruleset update can change results overnight).
