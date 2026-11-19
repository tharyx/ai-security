# Scorecard, SBOM tools and the Best Practices Badge (outline)

> **Status: hedged outline, not tested by the repo author.** Check each tool's current documentation.

**Course exercise:** Establish a vetting process for open-source components.
**Offline twin (tested):** [oss-vetting-process](../labs/oss-vetting-process/README.md).

## OpenSSF Scorecard

```text
# conceptual. Needs a GitHub token in the environment; read the README for the variable name.
scorecard --repo=github.com/<org>/<repo>
scorecard --repo=github.com/<org>/<repo> --format json > scorecard.json
```

- Public results for many projects are also available through the Scorecard web API and deps.dev (verify URLs).
- Map the JSON into the offline lab's `scorecard` dictionary (check name -> score) to feed `vetting.py` with real data.
- Add the Scorecard GitHub Action to your own repos and look at results in code scanning.

## SBOM and scanners (maintained choices, per the course brief)

| Task | Tool (check it is maintained) |
|---|---|
| Generate SBOM | Syft, Trivy, cdxgen (CycloneDX or SPDX output) |
| Match SBOM to vulnerabilities | Grype, Trivy, OSV-Scanner |
| Malicious package heuristics | GuardDog (Datadog); Socket-style services |
| Secrets | TruffleHog, gitleaks |
| Continuous SBOM monitoring | Dependency-Track |

Tools such as bomber, Tern or packj have uncertain maintenance: check the repository's activity first.

```text
# conceptual
syft dir:. -o cyclonedx-json > sbom.cdx.json
grype sbom:sbom.cdx.json
trivy sbom sbom.cdx.json
```

## Best Practices Badge

1. Sign in to bestpractices.dev with your GitHub account and add a project you maintain.
2. Answer the questionnaire; automatic detection fills some answers. Aim for **passing** first.
3. Add the badge to your README. Scorecard's `CII-Best-Practices` check will then notice it.
4. Treat silver and gold as long-term goals. Remember it is a self-assessment.
