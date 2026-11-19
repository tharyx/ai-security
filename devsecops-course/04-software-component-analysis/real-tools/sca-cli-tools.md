# Real tools: npm audit, RetireJS, Safety, pip-audit, osv-scanner, Snyk

> **Hedged guide.** Commands and exit codes change. Verify at each tool's documentation. These commands contact vendor or registry services, so run them only on projects you own, and keep tokens in CI secret variables, never in the repository. The course tests never need these tools.

## npm audit (JavaScript)

```text
npm ci                                 # install exactly what the lock file says
npm audit --audit-level=high           # non-zero exit when high or critical advisories exist
npm audit --omit=dev                   # production dependencies only
npm audit --json > npm-audit.json      # machine-readable for dashboards
```

- `npm audit fix` applies compatible updates; `--force` may apply breaking major upgrades, so use it on a branch with tests.
- Needs a lock file. Reports the dependency path, like the [lab](../labs/retirejs-npm-audit/README.md).

## RetireJS

```text
npm install -g retire                  # or run with npx; verify package and version
retire --path ./webapp                 # scan files for known-vulnerable JS libraries
retire --path ./webapp --severity high --outputformat json --outputpath retire.json
```

It identifies libraries from file names, contents and hashes, so it also sees files **copied into the repository** that `npm audit` cannot see. Check the current CLI options (severity, exit behaviour, offline repository file).

## Safety and pip-audit (Python)

```text
pip install safety pip-audit
safety check -r requirements.txt       # older command; newer versions use `safety scan` and may require an account. Verify.
pip-audit -r requirements.txt          # non-zero exit when vulnerable packages are found
pip-audit -r requirements.txt --format json --output pip-audit.json
```

- Safety's free database has limits and licence terms, so read them before using it in a commercial pipeline. **pip-audit** (maintained under the Python Packaging Authority, using PyPI and OSV data) is a current free alternative. This repository lists `pip-audit` in its own dev dependencies.
- Pin your requirements (`pip-compile` or a lock file). Unpinned ranges give unreliable answers, as the [lab](../labs/safety-pip-python/README.md) shows.

## osv-scanner

```text
osv-scanner --lockfile package-lock.json       # older style
osv-scanner scan source -L package-lock.json   # newer style; verify which your version uses
```

Reads lock files and SBOMs for many ecosystems and matches them to OSV, the same record format the labs use.

## Snyk

```text
snyk auth                       # interactive login; in CI use a token from a secret variable
snyk test --severity-threshold=high
snyk monitor                    # records a snapshot for continuous monitoring
```

Needs an account. Free tier limits and data-handling terms apply (manifests are sent to the service); check your organisation's policy. See the [CSE ch6 Snyk lab](../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/snyk-container-scan/README.md) for the container side.

## Generating an SBOM

Syft and Trivy can produce CycloneDX or SPDX documents; scanners such as Grype, Trivy and osv-scanner can then read them. See [CSE ch6](../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/README.md).

## CI skeleton (GitHub Actions style, sketch only)

```yaml
jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      # pin third-party actions to full commit SHAs in real pipelines
      - uses: actions/checkout@<sha>
      - run: npm ci
      - run: npm audit --audit-level=high --omit=dev
```

For GitLab CI or Jenkins the shape is the same: install from the lock file, run the scanner, let a non-zero exit code fail the job, store the JSON report as an artifact.
