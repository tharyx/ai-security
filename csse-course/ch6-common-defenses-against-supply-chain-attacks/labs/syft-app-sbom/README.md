# Lab: Generate the SBOM for Application using Syft

**Course exercise:** "Generate the SBOM for Application using Syft". Lesson: [04-asset-inventory-and-sboms.md](../../04-asset-inventory-and-sboms.md#22-application-sbom). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Syft**. Syft (Anchore) is actively maintained. Verify the current release and flags.

## What the offline twin does

`app_sbom.py` parses a `requirements.txt` (pinned, hashed, and one unpinned line) and an npm `package-lock.json` (v3 style) and emits **CycloneDX 1.5 JSON** with purls, hashes, licenses, scope and a reproducible serial number. `validate()` is a minimal structural check.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/syft-app-sbom/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/syft-app-sbom -v
```

1. Run the demo. Note the unpinned `urllib3>=2.0` is reported but not in the SBOM: why? (A range has no single resolved version; fix the lockfile.)
2. Add a package with a `--hash` line and confirm a `hashes` entry appears.
3. Change the app version and confirm the serial number changes but is stable for the same input.

## Expected output (real run)

```text
pinned: ['flask==3.0.3', 'requests==2.32.3', 'jinja2==3.1.4']
unpinned (not in SBOM, fix these): ['urllib3>=2.0']
specVersion: 1.5 | components: 6 | validation errors: []
  pkg:npm/%40scope/util@2.1.0 | optional | no-hash
  pkg:npm/express@4.19.2 | required | no-hash
  pkg:npm/qs@6.11.0 | required | no-hash
  pkg:pypi/flask@3.0.3 | required | no-hash
  pkg:pypi/jinja2@3.1.4 | required | no-hash
  pkg:pypi/requests@2.32.3 | required | hash
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# install: see the Syft README (package manager, release binary or container image); pin the version
syft dir:. -o cyclonedx-json=sbom.cdx.json
syft dir:. -o spdx-json=sbom.spdx.json
syft dir:. -o table                         # human-readable view
syft scan dir:. -o cyclonedx-json           # newer CLI spelling; check `syft --help`
```
Tips: generate from the **lockfile** in the build step; compare with a second generator (`cdxgen`, `trivy fs --format cyclonedx`) to spot gaps; store the file as a CI artifact (see [syft-in-cicd](../syft-in-cicd/README.md)).
