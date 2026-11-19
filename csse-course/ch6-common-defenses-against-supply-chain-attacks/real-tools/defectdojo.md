# DefectDojo (hedged)

> DefectDojo is an open-source vulnerability management and findings aggregation platform (OWASP project, actively maintained; verify). A real install uses several containers (web, database, queue), so it is optional for a low-disk laptop.

## Why it appears in a supply chain pipeline

Every scanner (Trivy, Semgrep, TruffleHog, ZAP, Kubescape, Syft/Grype) has its own output. A findings platform:

- **imports** reports (SARIF, JSON, CycloneDX) per product, engagement and test,
- **de-duplicates** findings across runs and tools,
- tracks **status** (active, false positive, risk accepted, mitigated) with notes and owners,
- applies **SLAs** by severity, and exports metrics.

## Typical flow

1. Create a **Product** (service) and an **Engagement** (CI run or release).
2. CI imports the scanner output through the API (token stored as a protected, masked CI variable):

```text
curl -sS -X POST "$DOJO_URL/api/v2/import-scan/" \
  -H "Authorization: Token $DOJO_TOKEN" \
  -F "scan_type=Trivy Scan" -F "engagement=<id>" -F "file=@trivy.json"
```

(Verify scan type names and parameters in the DefectDojo API docs. The `-F` form here sends only file and ids; never put untrusted values into form fields without `--form-string`.)

3. Triage in the UI: mark false positives with a justification; accept risk with an expiry.
4. Break the build only on **new** active findings above a threshold (query the API), as in [sast-in-pipeline](../labs/sast-in-pipeline/README.md).

## Offline practice

[false-positive-analysis](../labs/false-positive-analysis/README.md) models the triage and suppression workflow (justification, owner, expiry, fingerprint).

## Security notes

Change default credentials, restrict network access, back up the database, and review who can mark findings as false positives (it is a powerful permission).
