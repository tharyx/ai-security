# Lab: Finding Risky Packages using packj

**Course exercise:** "Finding Risky Packages using packj". Lesson: [02-evaluating-dependencies-before-use.md](../../02-evaluating-dependencies-before-use.md#13-openssf-scorecard-in-one-page). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **packj**. **Check packj's maintenance status before relying on it.** Alternatives: GuardDog for malicious behavior, OpenSSF Scorecard for project health, OSV-Scanner for known vulnerabilities, deps.dev for metadata.

## What the offline twin does

`risk_score.py` scores a package from metadata (maintainer count and account age, first and last release age, number of releases, downloads, repository link, archived or deprecated state, license) and from **capabilities detected in source** (network, subprocess, env access, file write, dynamic code, install script). Output is a score, a label and an explainable list of reasons.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/packj-risk-scoring/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/packj-risk-scoring -v
```

1. Run the demo and compare the three scores.
2. Add a second maintainer to `abandoned-lib` and see the score drop (a test does this).
3. Set your own threshold and decide what happens above it: block, or require review?

## Expected output (real run)

```text
== widely-used-lib: 6 LOW -> ALLOW
    +6 uses capabilities: network
== brand-new-helper: 97 HIGH -> REVIEW
    +8 single maintainer (bus factor 1)
    +15 maintainer account younger than 30 days
    +10 first release is less than 30 days old
    +5 only one release
    +5 very few downloads: little community review
    +8 no source repository link
    +6 no license declared
    +40 uses capabilities: dynamic-code, env-access, install-script, subprocess
== abandoned-lib: 30 MEDIUM -> ALLOW
    +8 single maintainer (bus factor 1)
    +12 no release for over 2 years (abandoned)
    +10 repository archived or package deprecated
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# packj (verify that it still installs and runs; check the repository)
pip install packj
packj audit pypi:<package>            # example form; check `packj --help` for current syntax
# Maintained alternatives
scorecard --repo=github.com/<owner>/<repo>     # OpenSSF Scorecard, repository practices
guarddog pypi scan <package>                   # malicious-behavior heuristics
osv-scanner scan source -L requirements.txt    # known vulnerabilities (check current subcommand names)
```
