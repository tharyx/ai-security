# Lab: Working with DefectDojo

**Course exercise:** "Working with Defect Dojo". Lessons: [04 section 5](../../04-best-practices-sbom-scorecard-and-badge.md#5-defectdojo-as-the-findings-hub) and [05](../../05-program-management.md). Diagram: [DefectDojo model](../../../../images/csse-ch7-defectdojo-model.svg). Real tool guide: [DefectDojo with Docker Compose](../../real-tools/defectdojo.md).

**Time:** 60 minutes. **Safety:** fixtures only; the model is a teaching twin, not the real DefectDojo.

## What it models

```text
Product > Engagement > Test > Finding
```

- **Importers**: `parse_sarif` (SARIF 2.1 results; severity from `security-severity` or the SARIF level; CWE from tags) and `parse_trivy` (Trivy JSON `Results[].Vulnerabilities[]`). Real DefectDojo has parsers for many scanners and uses the API `import-scan` and `reimport-scan`.
- **Deduplication**: a hash over chosen fields per scanner, or the scanner's own unique id. Scope can be one engagement or the whole product. Duplicates become inactive and point to the original.
- **Reimport**: a new scan of the same test closes findings that disappeared (mitigated) and reopens regressions.
- **Views**: open findings and counts by severity (duplicates, false positives and risk-accepted findings are excluded).

Hedge: DefectDojo's real dedup algorithms (unique-id, hash code, or a mix) and per-scanner hash fields are configurable; check the docs for your version.

## Steps

```text
.venv/Scripts/python csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/defectdojo-basics/demo.py
.venv/Scripts/python -m pytest csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/defectdojo-basics -v
```

1. Why does the lodash CVE found in two files count once? (The Trivy hash uses title, component and version, not the file.)
2. Change `HASH_FIELDS["Trivy Scan"]` to include `file_path`. What happens to the counts? Which choice is right for a monorepo?
3. Run with `dedupe_scope="engagement"` (see the test). When would you want per-engagement dedup? (Pen-test reports you want to keep separate.)
4. After `reimport_scan`, the fixed lodash finding is `mitigated`, not deleted. Why keep history? (MTTR, audits.)
5. Do the real version: [real-tools/defectdojo.md](../../real-tools/defectdojo.md).

## Expected output (real run)

```text
SARIF import      : {'created': 3, 'duplicates': 0}
Trivy import      : {'created': 2, 'duplicates': 1}
Trivy import again: {'created': 0, 'duplicates': 3}
open by severity  : {'Critical': 1, 'High': 2, 'Medium': 1, 'Low': 1, 'Info': 0}
new engagement    : {'created': 0, 'duplicates': 3} (product-wide dedup)
reimport after fix: {'created': 0, 'closed': 1, 'reopened': 0}
open by severity  : {'Critical': 1, 'High': 1, 'Medium': 1, 'Low': 1, 'Info': 0}
```

Tests: 18.
