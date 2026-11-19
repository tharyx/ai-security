# Lab: Secrets Scanning using TruffleHog

**Course exercise:** "Secrets Scanning using TruffleHog". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#31-application-code-sast-and-secrets). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **TruffleHog**. TruffleHog (Truffle Security) is actively maintained (verify). Its signature feature is **verification**: it calls the provider to check whether a credential is live.

## What the offline twin does

`truffle_lite.py` scans a **git history fixture** (four commits). A `FakeProvider` plays the provider's verification API **offline**: findings become `verified`, `unverified` or `unknown`. Shows that a secret removed in a later commit remains in history, why scanning only the latest checkout misses it, and how verification drives triage (rotate now vs likely dead vs review).

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan -v
```

1. Run the demo and read the three statuses.
2. Why does `current_tree_secrets` miss the key committed in `b2`? What do you do after finding a verified key? (Rotate/revoke first, then clean history if needed, then find usage in logs.)
3. Mark the Slack token live in the fake provider and see it move to the rotate-now bucket (you need a verifier for that detector in the real tool).

## Expected output (real run)

```text
verified   aws    AKIAIO...  commit b2 app.py
unverified aws    AKIAFA...  commit b2 old.env
unknown    slack  xoxb-0...  commit d4 notify.py
only-verified: [('b2', 'app.py')]
latest checkout alone sees: [('aws', 'old.env'), ('slack', 'notify.py')]
{'rotate-now': 1, 'review': 1, 'likely-dead': 1}
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
trufflehog git file://. --only-verified                    # local repo history, verified findings only
trufflehog git https://github.com/<org>/<repo> --since-commit <sha>
trufflehog filesystem ./src
trufflehog docker --image <image>@sha256:<digest>
trufflehog git file://. --json > findings.json
```
Verification makes **network calls to providers** with the found credential. Only run it on repositories you are authorized to scan, and understand that this contacts the provider with the candidate secret. Use `--no-verification` where that is not acceptable.
