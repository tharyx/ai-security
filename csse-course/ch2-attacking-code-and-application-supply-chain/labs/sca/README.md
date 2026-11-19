# Lab: Software Component Analysis (SCA)

**Course exercise:** "Software Component Analysis (SCA)". Lessons: [08 section 1](../../08-technologies-and-solutions-for-securing-applications.md#1-sca-software-composition-analysis), [07 section 1](../../07-best-practices-for-securing-the-application-supply-chain.md#1-sboms). Related: [CAISP ch4 third-party-vulns](../../../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/), [CAISP ch6 sbom-and-mlbom](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/), [vulnerability prioritization (CVSS/EPSS/KEV)](../../../../cybersecurity-track/08-vulnerability-management/README.md). Real tool: [real-tools/osv-scanner-and-syft.md](../../real-tools/osv-scanner-and-syft.md).

**Time:** 30 minutes. **Safety:** all package names and advisory ids are FICTIONAL (`EXAMPLE-2026-000N`). No network.

## What it does

`sca.py` reads a lock file (direct dependencies, and transitive ones marked `# via parent`) and a local advisory database (`introduced` and `fixed` versions), then reports affected packages with severity, fix version and who pulled them in. It compares versions **numerically** (so `1.10.0` is newer than `1.9.0`), supports an `ignore` list with a reason, and returns an exit code for a CI gate.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca
```

## Expected output (real run)

```text
[critical] EXAMPLE-2026-0002  yaml-lite==0.5.0 (via examplelib)  fix: 0.6.0  - unsafe object construction when loading documents (fictional)
[high    ] EXAMPLE-2026-0001  examplelib==1.3.0 (direct)  fix: 1.4.2  - path traversal in archive extraction (fictional)
[low     ] EXAMPLE-2026-0004  pdf-render-kit==2.0.1 (direct)  fix: 2.1.0  - excessive memory use on crafted input (fictional)
gate (fail on high) exit code: 1
```

## Break it yourself

1. Bump `examplelib` to `1.4.2`. Does `yaml-lite` stay flagged? (Only if the new `examplelib` still pins the old `yaml-lite`: the lock decides.)
2. Add `EXAMPLE-2026-0002` to the ignore list. Who should approve that, and when should it expire? (The security owner; give it an expiry. The lab keeps the reason string only.)
3. Add a rule for "package has no fix yet". What would you do? (Mitigate: pin, patch, replace, or accept with an expiry.)

## Limits

Real SCA also needs: reachability (is the vulnerable function used?), prioritization with CVSS/EPSS/KEV, license checks, and an SBOM as input. A match is "possibly affected", not "exploitable".
