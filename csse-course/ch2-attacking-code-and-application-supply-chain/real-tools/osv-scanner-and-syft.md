# OSV-Scanner, Syft, Grype and Trivy: SBOM and SCA on a real project

> **Status: hedged outline, not tested by the repo author.** These tools evolve quickly. Verify install steps and flags at <https://google.github.io/osv-scanner/>, <https://github.com/anchore/syft>, <https://github.com/anchore/grype> and <https://trivy.dev/>. They query vulnerability databases, so a real run needs a network (the repo's tests do not).

**Offline twins (tested):** [sca](../labs/sca/README.md) (lock file plus local advisories), [dependency-confusion](../labs/dependency-confusion/README.md) (hash lock). Related: [CAISP ch6 sbom-and-mlbom](../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/).

## What each does

| Tool | Role |
|---|---|
| **Syft** | generates an SBOM (CycloneDX or SPDX) from a directory, image or archive |
| **Grype** | scans an SBOM, directory or image for known vulnerabilities |
| **OSV-Scanner** | scans lock files, SBOMs and (optionally) images against OSV; can suggest fixes |
| **Trivy** | all-in-one: vulnerabilities, secrets, misconfigurations, licenses, SBOM; also images, repos and Kubernetes |
| **cdxgen** | CycloneDX SBOM generator for many ecosystems |

(Older tools such as bomber, Tern or packj may be unmaintained: check the repo's activity before relying on them.)

## Try it on the lab fixtures (outline)

```text
# 1. make an SBOM of a small project you own
syft dir:./my-small-project -o cyclonedx-json > sbom.cdx.json

# 2. match it against vulnerability data
grype sbom:./sbom.cdx.json
osv-scanner --sbom=sbom.cdx.json          # flag names differ across versions: check --help

# 3. scan a lock file directly
osv-scanner -L requirements.txt            # or the lock file of your ecosystem
```

The lab's `requirements.lock` uses fictional packages, so real databases will find nothing there. Use a small project of your own with a deliberately old dependency in a **throwaway directory**.

## What to compare with the lab

1. Direct versus transitive: does the tool show **who pulled in** the vulnerable package?
2. Fix versions: does it tell you the first fixed release?
3. Noise: how many findings are unreachable or low risk? Add **EPSS/KEV** prioritization ([vulnerability management lesson](../../../cybersecurity-track/08-vulnerability-management/README.md)).
4. Hash-locked installs: try `pip install --require-hashes -r requirements.txt` with a hash-generating tool (pip-compile `--generate-hashes`), then change one hash and watch the install refuse.

## Practices

- Generate the SBOM at **build time**, sign it, store it with the artifact ([lesson 07](../07-best-practices-for-securing-the-application-supply-chain.md)).
- Re-scan stored SBOMs on a schedule: new CVEs appear after release.
- Add **VEX** statements for findings that do not apply.
- Pin tool versions and database update policy in CI.

## Cleanup

Delete the SBOM and any cached vulnerability databases you do not need.
