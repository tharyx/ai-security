# Lab: Using TruffleHog/gitrob to scan for secrets in the CI/CD pipeline

**Course exercise:** "using trufflehog/gitrob to scan for secrets in CI/CD pipeline." Lessons: [02 secrets scanning and pre-commit](../../02-secrets-scanning-and-pre-commit.md). Related: [CSE ch6 trufflehog lab](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan/README.md) (provider verification offline), [CSE ch6 trivy-secrets-scan](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-secrets-scan/README.md), [false-positive-analysis](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/false-positive-analysis/README.md), [CMCPSE ch5 secret scanner](../../../../cmcpse-course/ch5-devsecops-for-mcp-security/02-sast-and-secret-scanning.md).

**Time:** 75 minutes. **Tests:** 13 (three of the history tests are skipped automatically when `git` is not installed). **Safety:** all secrets are **FAKE and built at runtime from pieces**; no source file contains a token-shaped literal. The history demo runs in a **temporary** repository with **isolated git config** (no system or global config, fixed dates, no prompts). No network, no real provider is called.

> **Outdated to current.** **gitrob is unmaintained** (verify). Use **TruffleHog**, **gitleaks** or **detect-secrets**. The file-name-signature idea of gitrob is kept here as one rule type.

## What it does

[secretscan.py](secretscan.py):

| Part | Detail |
|---|---|
| **Fake secrets** | `make_fake_token()` builds an internal-format token `acme_live_<20 chars><4-char checksum>` from pieces at runtime. `make_fake_private_key()` builds a fake key block. The format is invented, so it matches no real provider |
| **Rules** | Internal token regex with **checksum verification** (good checksum = HIGH, bad = LOW "probably test data"), private-key header, generic `password = "..."` with placeholder and low-entropy filters, a **Shannon entropy** rule that ignores UUIDs and hashes, and an allow-list pragma `# pragma: allowlist secret` |
| **gitrob-style file names** | `id_rsa`, `.pem`, `.env` (but not `.env.example`), `credentials` |
| **Redaction** | Output shows only a prefix and the length |
| **History scan** | `git log --all -p -U0` parsed for every **added line** on every branch; also file-name signatures; a **commit range** mode for CI |
| **Classification** | Each distinct secret is shown once at its first commit and marked "STILL IN HEAD" or "NOT in HEAD but STILL IN HISTORY" |
| **Gate** | `ci_gate()` fails at a chosen confidence |

`build_demo_repo()` creates a repo with three commits on `main` and a never-merged side branch: the token is added, then moved to an environment variable, then docs and a broken-checksum test token are added; the side branch has a second token in `notes.txt`.

## Run

```text
.venv/Scripts/python devsecops-course/05-static-analysis-and-secrets/labs/trufflehog-gitrob-secrets/demo.py
.venv/Scripts/python -m pytest devsecops-course/05-static-analysis-and-secrets/labs/trufflehog-gitrob-secrets -v
```

## Expected output (real run)

```text
== 1. fake secrets are built at runtime from pieces
valid checksum  -> [('acme-token', 'HIGH')]
broken checksum -> [('acme-token', 'LOW')]
placeholder     -> []
real-looking pw -> [('generic-assignment', 'MEDIUM')]
allowlisted     -> []
entropy of 'aaaaaaaaaaaa' vs random: 0.0 4.48

== 2. scan only the CURRENT files (what a naive scan does)
  [LOW   ] acme-token          tests/test_client.py:1 acme...(34 chars)       
           -> checksum FAILS: probably test data
gate (fail on MEDIUM) -> 0

== 3. scan the whole HISTORY on all branches
  [HIGH  ] acme-token          config.py:1            acme...(34 chars)        @2717412f 'initial import'
           -> checksum valid: treat as live; NOT in HEAD but STILL IN HISTORY (deleted later, or only on another branch): rotate it
  [MEDIUM] sensitive-filename  deploy/id_rsa          SSH private key file     @2717412f 'initial import'
           -> gitrob-style name signature; NOT in HEAD but STILL IN HISTORY (deleted later, or only on another branch): rotate it
  [HIGH  ] private-key-block   deploy/id_rsa:1        -----BEGIN ... PRIVATE KEY----- @2717412f 'initial import'
           -> NOT in HEAD but STILL IN HISTORY (deleted later, or only on another branch): rotate it
  [LOW   ] high-entropy-string deploy/id_rsa:2        7dxh...(40 chars)        @2717412f 'initial import'
           -> random-looking string; confirm by hand; NOT in HEAD but STILL IN HISTORY (deleted later, or only on another branch): rotate it
  [HIGH  ] acme-token          notes.txt:1            acme...(34 chars)        @bb70beb0 'wip notes (never merged)'
           -> checksum valid: treat as live; NOT in HEAD but STILL IN HISTORY (deleted later, or only on another branch): rotate it
  [LOW   ] acme-token          tests/test_client.py:1 acme...(34 chars)        @73c7ee93 'docs and tests'
           -> checksum FAILS: probably test data; STILL IN HEAD
gate (fail on MEDIUM) -> 1

== 4. CI mode: only the commits of this merge request (HEAD~1..HEAD)
  [LOW   ] acme-token          tests/test_client.py:1 acme...(34 chars)        @73c7ee93 'docs and tests'
           -> checksum FAILS: probably test data
gate (fail on MEDIUM) -> 0 | gate (fail on LOW) -> 1
```

## Steps

1. Part 1: a valid checksum is HIGH, a broken one LOW, a placeholder is ignored, a random password is MEDIUM, a pragma-allowed line is ignored. Entropy of a repeated letter is 0; a random token is about 4.5 bits per character.
2. Part 2: scanning only the **current files** finds just the LOW test token. The gate passes. This is the false sense of safety.
3. Part 3: scanning **history on all branches** finds the real token in `config.py` (first commit), the deleted key file, and the token on the **unmerged** branch. The gate fails. Each says "rotate it".
4. Part 4: **CI mode** scans only the last commit range, exactly what a merge-request job does. With `fail_on LOW` it fails on the test token, with `MEDIUM` it passes. Choose the threshold deliberately.
5. Add an allow-list rule for `tests/` with a **reason** and expiry. Why is a global allow-list dangerous?
6. Change the fake token function so the checksum is wrong in the real token and see the confidence drop. What would a real verification step (calling the provider) add, and what would it cost?

## Pre-commit versus CI (why this lab scans in CI)

A pre-commit hook can run this same scan on staged files, but the developer can skip it with `git commit --no-verify`, or never install it. The CI job is the enforcement point; see [lesson 02 section 5](../../02-secrets-scanning-and-pre-commit.md#5-why-pre-commit-hooks-are-not-a-good-fit-in-devsecops) and, for setting hooks up, the [CSE ch2 pre-commit lab](../../../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca-sast-pre-commit/README.md).

## Limits

- Real TruffleHog **verifies** candidates against provider APIs (network). The checksum here is an offline stand-in.
- A small rule set. Real tools ship hundreds of detectors.
- History scanning of large repositories is slow; scan the range in CI and the whole history on a schedule.

## Run the real tool (hedged, verify at source)

```text
trufflehog git file://. --since-commit <base> --only-verified
gitleaks detect --source . --redact
detect-secrets scan > .secrets.baseline
```

See [real-tools/secrets-tools.md](../../real-tools/secrets-tools.md). Never test with real credentials.
