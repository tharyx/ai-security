# Lab: Container Vulnerability Scanning using Snyk

**Course exercise:** "Container Vulnerability Scanning using Snyk". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#2-software-component-analysis-of-code-and-containers). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 7, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Snyk Container**. Snyk is a commercial product with a free tier; it needs an account and sends data to Snyk's service. Verify terms and your organization's policy before use. Open alternatives: Trivy, Grype.

## What the offline twin does

`snyk_lite.py` takes an **image package list** (base vs app origin) and a fictional advisory DB (ids `EXAMPLE-2026-xxxx`) and returns issues sorted by severity with **fix advice** (rebuild on newer base, bump lockfile, or no fix available), a **base-image recommendation** from a catalog, and a **severity-threshold gate**.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/snyk-container-scan/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/snyk-container-scan -v
```

1. Run the demo and read the advice lines. Which fixes belong to the platform team and which to the app team?
2. Why can a smaller base image have fewer issues? (Fewer packages installed.)
3. Raise and lower the gate threshold and note which pipeline stage would fail.

## Expected output (real run)

```text
[critical] EXAMPLE-2026-0102 zlib1g@1.2.13 (base)
[high    ] EXAMPLE-2026-0101 openssl@3.0.13 (base)
[medium  ] EXAMPLE-2026-0103 flask@3.0.3 (app)
advice:
  - zlib1g: no fixed version; consider a smaller base image or a compensating control
  - openssl: upgrade 3.0.13 -> 3.0.14 (rebuild on a newer base image)
  - flask: upgrade 3.0.3 -> 3.0.4 (bump the dependency in your lockfile)
recommended base image: distroless/static
gate high: FAIL | gate critical: FAIL
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
snyk auth                                            # opens a login; needs a Snyk account (do not paste tokens in chat or repos)
snyk container test <image>:<tag> --severity-threshold=high
snyk container test <image> --file=Dockerfile        # adds base-image upgrade advice
snyk container monitor <image>:<tag>                 # keep watching for new CVEs
```
CI tokens (`SNYK_TOKEN`) belong in protected, masked CI variables only.
