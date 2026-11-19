# Lab: False Positive Analysis (FPA)

**Course exercise:** "False Positive Analysis (FPA)". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#12-gating-rules-that-work). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **any scanner (Trivy, Snyk, Semgrep, DefectDojo)**. Every scanner has its own suppression format: Trivy `.trivyignore` / `.trivyignore.yaml`, Semgrep `# nosemgrep` and `.semgrepignore`, Snyk `.snyk` policy, GitLab vulnerability resolution, DefectDojo false-positive status. Verify the current syntax.

## What the offline twin does

`fpa.py` triages findings against a **YAML suppression file**. A suppression is valid only with a justification, an owner, a narrow rule and path, and an expiry within a year. Expired suppressions re-activate the finding. Fingerprints identify findings across runs. `metrics()` reports the false-positive rate.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/false-positive-analysis/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/false-positive-analysis -v
```

1. Run the demo and read the NOTES. Which suppressions were rejected and why?
2. Fix `SUP-4` by adding a real justification and see the md5 finding move to suppressed.
3. Rule of thumb: a false positive needs evidence (code path, test), a risk acceptance needs an owner and an expiry. Write one of each.

## Expected output (real run)

```text
ACTIVE:
  [CRITICAL] aws-access-key-id      config/prod.env
  [HIGH    ] subprocess-shell-true  build/make_docs.py
  [HIGH    ] EXAMPLE-2026-0001      requirements.txt
  [LOW     ] md5-usage              src/cache_keys.py
SUPPRESSED: [('generic-secret', 'SUP-1')]
NOTES:
  - SUP-2 expired on 2026-06-01: finding subprocess-shell-true re-activated
  - SUP-4 ignored: missing justification
{'total': 5, 'suppressed': 1, 'fp_rate': 0.2}
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# Trivy
echo "CVE-XXXX-YYYY  # reason, owner, expires 2027-03-01" >> .trivyignore
trivy fs --ignorefile .trivyignore --exit-code 1 .
# Semgrep (inline, with a reason)
#   dangerous_call()  # nosemgrep: rule-id  -- reviewed 2026-11, input is constant
# DefectDojo: mark the finding "False Positive" (with a note) or "Risk Accepted" with an expiry
```
Never suppress by path with a wildcard for a whole directory without a time limit and an owner.
