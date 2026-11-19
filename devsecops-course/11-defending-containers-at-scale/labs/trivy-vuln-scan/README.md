# Lab: Scanning images with Trivy (report parser and severity gate)

**Course exercises:** "Scanning Docker for Vulnerabilities With Trivy" [CCSE 4] and "Scanning docker images using Trivy and its APIs" [CDE 7] (first half). Lesson: [02 section 5](../../02-secure-images-linting-and-scanning.md#5-sca-of-images-and-choosing-a-scanner).

**Time:** 40 minutes. **Safety:** no scanner runs and no network is used; a Trivy JSON report is a fixture. CVE ids in it are fictional (`CVE-2099-xxxx`).

**Link, do not repeat:** the full scan-and-explain walk-through is [csse ch6 trivy-docker-scan](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-docker-scan/README.md); secrets scanning is [trivy-secrets-scan](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-secrets-scan/README.md). Here you work on what happens AFTER the scan: parse, summarise, gate.

## What it does

[trivy_report.py](trivy_report.py) reads the Trivy JSON structure (`Results[].Vulnerabilities[]`, `Secrets[]`, `Misconfigurations[]`), counts by severity, and applies a CI gate that mirrors `--severity`, `--ignore-unfixed`, `--ignorefile` and `--exit-code 1`.

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/trivy-vuln-scan/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/trivy-vuln-scan -v
```

1. Run the three gates. Why does `CRITICAL` fail fewer things than `HIGH`?
2. `--ignore-unfixed` hides CVE-2099-0002 (no fix). Is that safe? (It reduces noise but the risk is still there: track it, do not forget it.)
3. Read [trivyignore.txt](fixtures/trivyignore.txt): the comment records owner and expiry. An ignore without an expiry is a permanent blind spot.

## Expected output (real run)

```text
summary: {'CRITICAL': 2, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 1, 'UNKNOWN': 0}
secrets: ['generic-fake-secret'] | failed misconfigs: ['DS002', 'DS026']
-- HIGH gate: FAIL (5 reasons)
    CRITICAL CVE-2099-0001 libfoo1 1.2.3-1 -> fix 1.2.3-2
    HIGH CVE-2099-0002 libbar 0.9-4 -> fix none
    HIGH CVE-2099-0100 flaskish 2.0.0 -> fix 2.0.4
    CRITICAL CVE-2099-0101 yamlish 5.1 -> fix 5.4
    SECRET generic-fake-secret in app/.env:3
-- CRITICAL gate: FAIL (3 reasons)
    CRITICAL CVE-2099-0001 libfoo1 1.2.3-1 -> fix 1.2.3-2
    CRITICAL CVE-2099-0101 yamlish 5.1 -> fix 5.4
    SECRET generic-fake-secret in app/.env:3
-- HIGH + ignore-unfixed + trivyignore: FAIL (3 reasons)
    CRITICAL CVE-2099-0001 libfoo1 1.2.3-1 -> fix 1.2.3-2
    CRITICAL CVE-2099-0101 yamlish 5.1 -> fix 5.4
    SECRET generic-fake-secret in app/.env:3
```

## Run the real tool (hedged)

```text
trivy image --format json --output report.json --severity HIGH,CRITICAL --ignore-unfixed registry.example.invalid/shop/api:1.4.0
trivy image --exit-code 1 --severity CRITICAL registry.example.invalid/shop/api:1.4.0
```

Trivy downloads its vulnerability database on first use (use a mirror or `--skip-db-update` in air-gapped CI). Flags change between releases: verify with `trivy image --help`. See [real-tools](../../real-tools/README.md).
