# Real tools: TruffleHog, gitleaks, detect-secrets, pre-commit

> **Hedged guide.** Flags and exit codes change. Verify at each project's documentation. **Never scan or paste real credentials into a tool you do not trust; never commit a real secret to test a scanner.** Use FAKE values. TruffleHog's verification feature sends candidate secrets to the provider's API to check them, so use it only on secrets you own and are allowed to test.

## gitrob (legacy)

The syllabus names **gitrob**, which looked at repository **file names and paths** (SSH keys, `.pem`, `.env`) across an organisation. It is **unmaintained** (verify). The file-name-signature idea survives in the lab and in modern scanners; use TruffleHog, gitleaks or detect-secrets.

## TruffleHog (v3)

```text
trufflehog git file://. --since-commit <base> --only-verified     # scan a commit range; report only verified secrets
trufflehog git file://. --fail                                      # exit non-zero when results are found (verify flag)
trufflehog filesystem ./src                                         # scan a directory
```

- Many detectors with **verification**; `--only-verified` gives few false positives but needs network access to the providers.
- In CI, scan the **merge request range**, and schedule a full-history scan.

## gitleaks

```text
gitleaks detect --source . --redact --report-format sarif --report-path gitleaks.sarif   # older command style
gitleaks git . --redact                                                                  # newer command style; verify which your version uses
gitleaks protect --staged                                                                # pre-commit style scan (older versions)
```

- Rules in a TOML file; add your **own rules** for internal token formats (regex, keywords, entropy, allow-lists).
- Use `--redact` so the secret does not appear in CI logs.
- A `.gitleaksignore` file lists accepted fingerprints; keep reasons in comments.

Custom rule sketch (shape only, verify the schema in your version):

```toml
[[rules]]
id = "acme-internal-token"
description = "Internal service token"
regex = '''acme_live_[A-Za-z0-9]{24}'''
keywords = ["acme_live_"]
```

## detect-secrets (Yelp)

```text
detect-secrets scan > .secrets.baseline        # create a baseline of known findings
detect-secrets audit .secrets.baseline         # mark each as real or false positive
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)   # fail on NEW secrets
```

Inline allow-list comment: `# pragma: allowlist secret` (the lab honours the same pragma).

## GitHub and GitLab built-ins

- **GitHub secret scanning** and **push protection** can block a push that contains a known secret format (verify availability for your plan and repository type).
- GitLab offers secret detection in its pipeline templates and secret push protection (verify edition and version).

## pre-commit framework (convenience, not a gate)

```yaml
# .pre-commit-config.yaml (sketch: pin `rev` to a real tag or commit; verify the repo URL)
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: <pinned tag>
    hooks:
      - id: gitleaks
```

```text
pre-commit install                    # per clone, easy to forget
pre-commit run --all-files            # run the same hooks in CI as the enforced check
```

A developer can bypass it with `git commit --no-verify`, so **repeat the scan in CI** and protect the branch so the CI job must pass ([lesson 02](../02-secrets-scanning-and-pre-commit.md)). See the CSE labs on [pre-commit hooks](../../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/pre-commit-hooks/README.md) and [attacks on them](../../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/exploiting-pre-commit-hooks/README.md).

## If a scanner finds a real secret

Revoke and rotate first, check logs, fix the code path, add scanning to CI, and only then consider rewriting history (`git filter-repo` or BFG). See [lesson 02 section 4](../02-secrets-scanning-and-pre-commit.md#4-responding-to-a-leaked-secret-the-order-matters).
