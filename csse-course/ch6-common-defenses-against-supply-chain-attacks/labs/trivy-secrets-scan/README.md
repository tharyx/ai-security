# Lab: Secrets Scanning using Trivy

**Course exercise:** "Secrets Scanning using Trivy". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#31-application-code-sast-and-secrets). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 40 minutes. **Tests:** 8, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Trivy**. Trivy (Aqua Security) is actively maintained. Verify flags; the secret scanner is enabled with `--scanners secret`.

## What the offline twin does

`secret_scan.py` implements **regex rules + keyword + entropy filter**, allow-rules for paths, an ignore list of rule ids, redacted matches, Trivy-style JSON output and an exit code. Every secret in the fixtures is **FAKE** (AWS's documented example key id, repeated `FAKE` strings).

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-secrets-scan/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-secrets-scan -v
```

1. Run the demo. Which rule found `SECRET_KEY` in `settings.py`? Why does the entropy filter matter?
2. Add a new rule for a made-up token prefix `corp_` and confirm it fires.
3. Why are `tests/*` and `*.md` allow-listed? What is the risk of allow-listing too much? (Real secrets pasted into a test file.)

## Expected output (real run)

```text
[CRITICAL] config/app.env     line 2  aws-access-key-id  AKIA****************
[CRITICAL] src/client.py      line 1  github-pat         ghp_************************************
[HIGH    ] deploy/key.pem     line 1  private-key        ----***************************
[MEDIUM  ] src/settings.py    line 1  generic-secret     q9X7****************************
exit code (fail on CRITICAL/HIGH): 1
exit code with aws rule ignored   : 0
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
trivy fs --scanners secret .                              # scan a directory
trivy fs --scanners secret --format json -o secrets.json .
trivy image --scanners secret <image>@sha256:<digest>      # secrets baked into image layers
trivy fs --scanners secret --exit-code 1 .                 # fail the CI job on findings
# custom rules and allow rules go in trivy-secret.yaml (check the Trivy docs for the schema)
```
Rotate any real secret you find; removing it from the repository is not enough (it stays in history, see the [trufflehog lab](../trufflehog-secrets-scan/README.md)).
