# Lesson 04: Software Supply Chain Best Practices (SBOM, CycloneDX, OpenSSF, CII) and DefectDojo

> **Chapter:** 7 · Managing a Secure Software Supply Chain Program · **Time:** ~5 hours
> **You will:** produce and read an SBOM, compare CycloneDX and SPDX, list Scorecard's automated checks, explain the Best Practices Badge levels, and use DefectDojo as a findings hub.

| | |
|---|---|
| **Prerequisites** | [Lesson 03](03-standards-and-frameworks.md) |
| **Labs** | [defectdojo-basics](labs/defectdojo-basics/README.md) · [oss-vetting-process](labs/oss-vetting-process/README.md) (Scorecard-like scoring) |
| **Syllabus lines** | Software Supply Chain Best Practices · SBOM · CycloneDX · OpenSSF – Automated · Core Infrastructure Initiative – Self Assessment · Working with Defect Dojo |
| **Diagram** | [DefectDojo model](../../images/csse-ch7-defectdojo-model.svg) |
| **Reuse** | [CAISP SBOM and MLBOM lab](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/) · [CMCPSE SBOM lab](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sbom-mcp-server/README.md) · [CAASE AIBOM](../../caase-course/ch6-operationalizing-agentic-ai-security/README.md) |

> **Hedge.** Spec versions and criteria count change. "Verify at source" applies to every number.

## 1. SBOM

A **Software Bill of Materials** is a machine-readable inventory of the components inside a piece of software, with their relationships. Think of the ingredient list on food.

| Topic | Detail |
|---|---|
| **Why** | Answer "do we run X?" in minutes (Log4Shell lesson); feed vulnerability matching; license compliance; supplier transparency; regulation (US EO 14028 follow-ups, EU CRA documentation). |
| **NTIA minimum elements (2021)** | Supplier name, component name, version, other unique identifiers (purl, CPE, hash), dependency relationship, author of SBOM data, timestamp. CISA proposed an updated minimum-elements list in 2025: verify its status. |
| **Types** | Source, build, analyzed (from an artifact), deployed, runtime. Different stages give different accuracy. |
| **Generate** | Syft, Trivy, cdxgen, and language tools (for example CycloneDX plugins for Maven, npm, Python). Generate **at build time** from the lockfile and the final image. |
| **Consume** | Grype, Trivy, OSV-Scanner (match against vulnerability data); Dependency-Track (continuous monitoring platform); DefectDojo (findings). |
| **Pitfalls** | Generated once and never updated; missing transitive or vendored code; no purl so matching is weak; treating SBOM as proof of security. |
| **VEX** | **Vulnerability Exploitability eXchange**: a statement that a listed CVE is *not affected*, *affected*, *fixed*, or *under investigation* for a product. It cuts false positives. CycloneDX and CSAF/OpenVEX carry it. |

## 2. CycloneDX (and how it compares with SPDX)

| | **CycloneDX** | **SPDX** |
|---|---|---|
| Origin | OWASP; standardized as **ECMA-424** (verify edition) | Linux Foundation; **ISO/IEC 5962:2021** for SPDX 2.2.1 |
| Born for | Security and risk use cases | License compliance (now broader) |
| Versions | 1.4, 1.5, 1.6, and newer (verify the latest) | 2.2, 2.3, **3.0** (2024, reworked data model) |
| Formats | JSON, XML, Protobuf | JSON, YAML, tag-value, RDF; 3.0 uses JSON-LD |
| Strengths | Compact; first-class **VEX**, services, vulnerabilities; extended BOM types: **SaaSBOM, HBOM, CBOM** (cryptography), **ML-BOM** | Rich license and file-level data; legal ecosystem; relationships |
| Use when | Security tooling, vulnerability workflows, AI/ML BOMs | Legal/compliance, or a customer demands SPDX |

Both are accepted by US and EU guidance. Many tools can convert; generate one primary format and convert when asked.

A minimal CycloneDX component (illustrative):

```json
{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
 "components": [{"type": "library", "name": "lodash", "version": "4.17.20",
                 "purl": "pkg:npm/lodash@4.17.20",
                 "hashes": [{"alg": "SHA-256", "content": "<digest>"}]}]}
```

Hands-on in the repo: [CAISP sbom-and-mlbom](../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/sbom-and-mlbom/) generates and checks a BOM offline.

## 3. OpenSSF – Automated: Scorecard

**OpenSSF Scorecard** runs automated checks on an open-source repository (GitHub mainly; GitLab support is more limited, verify) and gives each check a score from 0 to 10, plus an overall score. `-1` means "could not determine". It is the **automated** part of the syllabus's "OpenSSF – Automated".

Checks (list as the author recalls it; run `scorecard --help` or read the docs for the current set):

| Group | Checks |
|---|---|
| **Code** | Binary-Artifacts, Dangerous-Workflow, Dependency-Update-Tool, Pinned-Dependencies, SAST, Fuzzing, Vulnerabilities |
| **Process** | Branch-Protection, Code-Review, CI-Tests, Contributors, Maintained, Security-Policy, License |
| **Release** | Signed-Releases, Token-Permissions, Packaging, SBOM (newer; verify) |
| **Other** | CII-Best-Practices (reads the badge from section 4), Webhooks (experimental or removed: verify) |

Each check has a **risk** weighting (critical, high, medium, low) that feeds the overall score.

How to use it:
- **Before adopting** a dependency (vetting criterion, see [lab](labs/oss-vetting-process/README.md)). Public results exist via the Scorecard API and on deps.dev.
- **On your own repos** with the Scorecard GitHub Action, results go to code scanning.
- **Caveats:** a score is a *proxy*; a small, well-run project may score low on checks that need a big team (Code-Review needs more than one person). Read the individual checks.

```text
# conceptual CLI (hedged; needs a GitHub token in the environment)
scorecard --repo=github.com/<org>/<repo>
```

See [real-tools](real-tools/README.md) for the Scorecard and badge notes.

## 4. Core Infrastructure Initiative: Self Assessment (the Best Practices Badge)

The **CII Best Practices Badge** started in the Core Infrastructure Initiative (Linux Foundation, created after Heartbleed in 2014). The program moved to the **OpenSSF**, so today it is the **OpenSSF Best Practices Badge** (bestpractices.dev). It is a **self-assessment**: project maintainers answer a questionnaire about their practices; the site runs some automatic checks; the claims are public.

| Level | What it means (verify the criteria on the site) |
|---|---|
| **Passing** | Baseline good practices: public version control, a documented way to report vulnerabilities, a build and tests, basic secure development knowledge, working HTTPS, static analysis, fixing known vulnerabilities promptly, no leaked credentials. Roughly 60 to 70 criteria. |
| **Silver** | More rigorous: for example a governance and roles model, a code of conduct, stronger review and security documentation, reproducible build goals, signed releases. |
| **Gold** | Highest: for example two or more unassociated significant contributors, a high test coverage target, a hardening and dynamic analysis expectation, a security review. |

Notes: the program has also been extended with **baseline** tiers aligned to the OpenSSF Baseline work (verify). Scorecard's `CII-Best-Practices` check reads whether a project has a badge, so the two connect: automated measurement plus self-attestation.

**Self-assessment strengths and limits:** cheap and a good checklist; but it relies on honesty and is not an audit. Use the badge as one signal and verify with Scorecard and your own review.

## 5. DefectDojo as the findings hub

**DefectDojo** is an open-source application vulnerability management and orchestration platform (maintained, with a community edition and a commercial offering: verify the current editions). It collects results from many scanners into one place so that you can deduplicate, triage, track SLAs and report.

| Concept | Role |
|---|---|
| **Product** (and product type) | An application or service; ownership and access scope |
| **Engagement** | A time-boxed or CI-run activity: a release, sprint, pen test |
| **Test** | One scan run with a given scan type |
| **Finding** | The vulnerability: severity, status, component, hash code |
| **Import / Reimport** | API calls (`import-scan`, `reimport-scan`): create new, or update an existing test and close what is no longer reported |
| **Deduplication** | By hash fields or scanner IDs, per product or engagement scope |
| **SLA, risk acceptance, false positive** | Governance workflow ([lesson 05](05-program-management.md), [lab](labs/vuln-management-defectdojo/README.md)) |
| **Integrations** | Push to Jira or GitHub issues, notifications, metrics dashboards, parsers for scanners like Trivy, Semgrep, Dependency-Check, OSV, Gitleaks |

Typical pipeline: `CI job -> scanner (SARIF/JSON) -> DefectDojo reimport-scan -> tickets -> dashboard`. In your course lab you may also meet a SBOM or VEX import: check the parser list for your version.

Hands-on: [defectdojo-basics](labs/defectdojo-basics/README.md) (offline model with SARIF and Trivy importers and dedup) and the hedged [real DefectDojo guide](real-tools/defectdojo.md).

## 6. Hands-on

1. Generate an SBOM for a small project in your course lab with Syft or cdxgen (hedged guides in [real-tools](real-tools/README.md)); feed it to Grype or Trivy; compare results.
2. Pick one dependency from the [vetting fixtures](labs/oss-vetting-process/fixtures/intel.json) and compute its score by hand using the weights in `vetting.py`.
3. Run [defectdojo-basics](labs/defectdojo-basics/README.md).

## 7. Scenarios

1. **Customer asks for an SBOM in SPDX; you use CycloneDX.** Convert, but check that the purls and hashes survived; keep the CycloneDX original as the source of truth.
2. **Scanner floods you with CVEs in unused code.** Add VEX statements (not affected: code not reachable) and reachability analysis; DefectDojo false-positive workflow with review.
3. **Great Scorecard, no badge** (or the reverse). Scorecard measures observable repo settings; the badge covers documentation and process. They answer different questions.

## 8. Common mistakes

- One-time SBOM in a release folder, never refreshed.
- Using NVD CPE matching only and ignoring purl-based sources such as OSV.
- Reading the Scorecard overall number and skipping the failing check that matters (for example Dangerous-Workflow).
- Treating the badge as a security audit.
- Pasting scanner output into spreadsheets instead of a deduplicating hub.

## 9. Interview Q&A

<details><summary><b>Q1. CycloneDX or SPDX?</b></summary>
Both are valid. CycloneDX is security-oriented, compact, with VEX and extra BOM types (SaaS, hardware, crypto, ML). SPDX is strong on licenses and legal use and has an ISO standard (2.2.1); SPDX 3.0 broadens the model. Choose by use case and customer demand, and be able to convert.
</details>

<details><summary><b>Q2. What is VEX and why do you need it?</b></summary>
A statement about whether a product is actually affected by a given vulnerability in one of its components (not affected, affected, fixed, under investigation). It removes false positives so teams spend time on real exposure.
</details>

<details><summary><b>Q3. Give five Scorecard checks and what risk each addresses.</b></summary>
Branch-Protection (unreviewed pushes), Code-Review (single-person changes), Dangerous-Workflow (CI injection), Pinned-Dependencies (mutable references), Signed-Releases (tampered releases). Also Token-Permissions, Vulnerabilities, Maintained.
</details>

<details><summary><b>Q4. What are the Best Practices Badge levels and who assesses them?</b></summary>
Passing, silver, gold. The project maintainers assess themselves in a questionnaire with some automated checks, so it is a self-assessment, not an audit. Formerly the CII badge, now OpenSSF.
</details>

<details><summary><b>Q5. What is the difference between import-scan and reimport-scan in DefectDojo?</b></summary>
Import creates a new test with the results. Reimport updates an existing test: new findings are created, unchanged ones kept, and findings missing from the new scan are closed as mitigated.
</details>

## 10. Checklist

- [ ] I can name the NTIA minimum SBOM elements and what VEX adds.
- [ ] I can compare CycloneDX and SPDX in a table without notes.
- [ ] I can list at least ten Scorecard checks.
- [ ] I can state badge levels and why it is a self-assessment.
- [ ] I can describe the DefectDojo hierarchy and dedup.

## 11. References

- CycloneDX (cyclonedx.org) and ECMA-424; SPDX (spdx.dev); NTIA "Minimum Elements for an SBOM" (2021); CISA SBOM resources.
- OpenSSF Scorecard (github.com/ossf/scorecard), checks documentation.
- OpenSSF Best Practices Badge (bestpractices.dev).
- DefectDojo documentation (docs.defectdojo.com): import and reimport, deduplication, SLA.
- Next: [Lesson 05: program management](05-program-management.md).
