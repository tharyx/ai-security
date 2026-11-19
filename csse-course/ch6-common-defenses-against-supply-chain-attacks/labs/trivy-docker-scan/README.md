# Lab: Scanning Docker for Vulnerabilities with Trivy

**Course exercise:** "Scanning Docker for Vulnerabilities with Trivy". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#2-software-component-analysis-of-code-and-containers). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Trivy**. Trivy is actively maintained. Verify flags and DB download behavior (Trivy downloads its vulnerability DB; plan for offline or mirrored DBs in restricted networks).

## What the offline twin does

`trivy_lite.py` reads **dpkg status text** from an image fixture, matches a fictional OSV-like advisory DB with **Debian-style version comparison** (epochs, suffixes), and offers the CI knobs: `--severity`, `--ignore-unfixed`, an ignore list and an **exit code**, with a Trivy-like table.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-docker-scan/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-docker-scan -v
```

1. Run the demo. Why is the CRITICAL finding still shown with `--ignore-unfixed` off, and hidden when it is on?
2. Patch the versions in the fixture and re-run until the only finding is the one without a fix.
3. Decide: should an unfixed CRITICAL block a release? Write the policy and the exception process.

## Expected output (real run)

```text
Library  Vulnerability      Severity  Installed              Fixed
zlib1g   EXAMPLE-2026-0202  CRITICAL  1:1.2.13.dfsg-1        -
openssl  EXAMPLE-2026-0201  HIGH      3.0.13-1~deb12u1       3.0.14
curl     EXAMPLE-2026-0203  MEDIUM    7.88.1-10+deb12u5      7.88.1-10+deb12u6
bash     EXAMPLE-2026-0204  LOW       5.2.15-2+b7            5.2.15-2+b8
exit code: 1
--severity HIGH,CRITICAL --ignore-unfixed -> ['EXAMPLE-2026-0201']
with ignore file for the CRITICAL id      -> exit 1
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
trivy image <image>@sha256:<digest>
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 <image>
trivy image --format json -o trivy.json <image>
trivy image --format cyclonedx -o image.cdx.json <image>      # SBOM from the same tool
trivy image --scanners vuln,secret,misconfig <image>
```
Pin the Trivy version in CI, cache the DB, and treat a failure to download the DB as a pipeline failure (not a pass).
