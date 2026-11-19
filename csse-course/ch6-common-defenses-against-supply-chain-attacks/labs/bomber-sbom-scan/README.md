# Lab: Scan SBOM for Vulnerabilities using bomber

**Course exercise:** "Scan SBOM for Vulnerabilities using bomber". Lesson: [04-asset-inventory-and-sboms.md](../../04-asset-inventory-and-sboms.md#25-operating-sboms). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 45 minutes. **Tests:** 9, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **bomber**. **Check bomber's maintenance status before relying on it.** Maintained alternatives: Grype (`grype sbom:`), OSV-Scanner (`osv-scanner --sbom`), Trivy (`trivy sbom`), Dependency-Track.

## What the offline twin does

`bomber_lite.py` reads a **CycloneDX SBOM**, parses purls and matches them against a **local OSV-format database** (introduced/fixed ranges, aliases, severity). It reports components that cannot be matched (no purl), supports ignore lists by id or alias, a summary and an exit code threshold. Advisory ids are fictional.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/bomber-sbom-scan/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/bomber-sbom-scan -v
```

1. Run the demo. Why is `mystery` listed as unmatched? (No purl, so no reliable match: a data-quality finding.)
2. Add an OSV record for `flask` and re-scan.
3. Add the alias of an advisory to the ignore list and confirm it is silenced; where should that decision be recorded? (An expiring exception file.)

## Expected output (real run)

```text
[CRITICAL] express@4.17.1     EXAMPLE-OSV-0002 fixed in 4.19.2
[HIGH    ] imagelib@1.2.0     EXAMPLE-OSV-0001 fixed in 1.2.5
unmatched components (no purl): ['mystery']
summary: {'total': 2, 'unmatched': 1, 'CRITICAL': 1, 'HIGH': 1} | exit code: 1
ignoring the critical id -> exit 0
```

## Real-tool guide (hedged: verify commands against the current docs)

```text
# bomber (verify it is still maintained for your needs)
bomber scan sbom.cdx.json
bomber scan --output json sbom.cdx.json
# Maintained alternatives
grype sbom:sbom.cdx.json --fail-on high
osv-scanner scan --sbom sbom.cdx.json          # check the exact flag in your version
trivy sbom sbom.cdx.json
```
Most scanners download a vulnerability database; use a mirror or pre-downloaded DB in restricted networks.
