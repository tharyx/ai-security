# Lesson 05: Running a Supply Chain Security Program

> **Chapter:** 7 · Managing a Secure Software Supply Chain Program · **Time:** ~3 hours
> **You will:** define roles, KPIs, SLAs and an exception process for a supply chain program, and tie it to EO 14028 and the EU Cyber Resilience Act.

| | |
|---|---|
| **Prerequisites** | [Lessons 01 to 04](01-supply-chain-attack-visibility.md) |
| **Labs** | [vuln-management-defectdojo](labs/vuln-management-defectdojo/README.md) · [defectdojo-basics](labs/defectdojo-basics/README.md) |
| **Syllabus lines** | supports every line of the chapter, especially "Vulnerability Management With DefectDojo" |
| **Reuse** | [cybersecurity-track 08](../../cybersecurity-track/08-vulnerability-management/README.md) (lifecycle, scanners, prioritization, remediation) · [08-ai-compliance control mapping and evidence](../../08-ai-compliance/03-control-mapping-and-evidence.md) · [07-ai-governance](../../07-ai-governance/README.md) |

> **Hedge.** Laws and deadlines below are as reported to Nov 2026. Verify at source and ask legal counsel for decisions.

## 1. Program shape

A program is: **policy, people, process, tooling, and evidence**, run on a cycle.

```text
Policy  ->  Inventory  ->  Vet / Build securely  ->  Scan and monitor  ->  Triage and fix  ->  Evidence and report  ->  (improve policy)
```

Start small: inventory + intake gate + SLA for criticals. Then add provenance, then maturity targets (SLSA level, S2C2F level, SCVS level) by risk tier.

## 2. Roles (RACI-style)

| Role | Responsibility |
|---|---|
| **Executive sponsor / CISO** | Owns risk appetite, approves exceptions above a threshold, reports to the board |
| **Program owner (product security / supply chain lead)** | Runs the program, KPIs, tooling roadmap |
| **Engineering managers and service owners** | Own fixes inside the SLA; own their dependency list |
| **Developers** | Request components, update dependencies, respond to findings |
| **Platform / DevOps** | Build pipelines, registry mirror, signing, provenance, admission policy |
| **Security champions** | Embedded triage and education in teams |
| **Vulnerability management / AppSec triage** | Deduplicate, validate, assign, review false positives |
| **Legal / procurement** | License policy, vendor contracts, SBOM and disclosure clauses |
| **PSIRT / incident response** | Handle vulnerabilities in your own products, coordinated disclosure, regulators |
| **Internal audit / GRC** | Evidence review, control testing ([evidence mapping](../../08-ai-compliance/03-control-mapping-and-evidence.md)) |

## 3. SLAs: example policy

Vulnerabilities get a **time limit by severity**, adjusted by exploitability. Example (set your own; many teams start here and verify what DefectDojo's default SLA settings are):

| Severity | Fix SLA (example) | Notes |
|---|---|---|
| Critical | 7 days | Internet-facing or KEV-listed: hours to 3 days |
| High | 30 days | EPSS high: pull forward |
| Medium | 90 days | |
| Low | 120 days or next release | |
| Info | no SLA | |

Other SLAs: **intake decision** within 3 business days; **vendor SBOM** within 30 days of request; **incident response for a poisoned dependency**: "is it in our estate?" answered in 1 hour, mitigation started the same day.

Run these with the [vuln-management lab](labs/vuln-management-defectdojo/README.md). Ranking inside a bucket uses CVSS, EPSS and KEV ([prioritizer lab](../../cybersecurity-track/08-vulnerability-management/lab/vm_prioritizer.py)).

## 4. Exceptions (risk acceptance)

Not every finding can be fixed on time. An exception process keeps that honest:

| Rule | Why |
|---|---|
| Written justification and **compensating controls** | Shows the risk is understood |
| Different **approver** than the owner; higher level for higher severity | Separation of duties |
| Always **expires** (for example 30 to 180 days) | "Temporary" must not become permanent |
| **No exceptions** for known-exploited vulnerabilities without an exception board | Highest real-world risk |
| Expiry **reactivates** the finding; the SLA clock does not restart | Prevents timer resets |
| Tracked and **reported** (count, age, owner) | Visible to leadership |

## 5. KPIs and metrics

Choose a few that drive decisions. Avoid vanity numbers (total CVEs found).

| KPI | Definition | Good direction |
|---|---|---|
| **MTTR by severity** | Mean days from found to mitigated | Down |
| **SLA compliance** | Share of findings fixed within SLA | Up (target, for example, 90% or more for criticals) |
| **Open by severity and age** | Backlog size and aging buckets | Down |
| **Overdue count** | Findings past SLA, by team | Zero for critical |
| **Exception count and age** | Active risk acceptances, days to expiry | Down, none expired unreviewed |
| **SBOM coverage** | Share of released artifacts with a current SBOM | 100% |
| **Provenance coverage and verification rate** | Share of artifacts with SLSA provenance, and share verified at deploy | Up |
| **Pinned/locked ratio** | Share of repos with lockfiles and SHA-pinned CI actions | Up |
| **Intake lead time** | Request to decision | Down, within SLA |
| **Dependency freshness / "time to adopt a fix"** | Days from fix release to your deployment | Down |
| **Mean time to answer "do we use X?"** | Inventory query time in an incident | Minutes |
| **Scorecard of own repos** | Average Scorecard score of your critical repos | Up |

Report **trends and medians** to executives, **lists and owners** to engineers.

## 6. Regulatory and customer drivers

| Driver | What it asks (hedged) | Program link |
|---|---|---|
| **US EO 14028 (May 2021)** | Improve software supply chain security: NIST guidance (SSDF), SBOM, secure development attestation for suppliers to the federal government (OMB M-22-18 and M-23-16; the CISA attestation form from 2024). **EO 14306 (June 2025)** amended parts of the cyber orders; verify what remains in force. | SSDF mapping, attestation evidence, SBOMs |
| **EU Cyber Resilience Act (Regulation (EU) 2024/2847)** | Cybersecurity requirements for products with digital elements sold in the EU. **Reporting** of actively exploited vulnerabilities and severe incidents to ENISA and national CSIRTs (early warning within 24 hours) applies from **11 Sept 2026**; most other obligations apply from **11 Dec 2027**. Manufacturers must handle vulnerabilities during the support period, provide security updates, document components (an SBOM in a common machine-readable format is part of the technical documentation), and exercise due diligence on third-party components, including open source they integrate. | SBOM, vulnerability handling, intake vetting, PSIRT process |
| **NIST SP 800-161 Rev.1 (C-SCRM)** | Supplier risk program | Policy, supplier tiers, contract clauses |
| **NIS2 (EU)** | Supply chain security in risk management measures for essential and important entities | Supplier assessments |
| **PCI DSS 4.0, SOC 2, ISO 27001** | Inventory, vulnerability and change controls often asked in audits | Evidence from the same tools |
| **Customer questionnaires** | SBOM, SLSA, attestations | Reuse evidence |

**One evidence base, many frameworks.** Build the mapping once: control -> evidence artifact -> frameworks it satisfies. See [control mapping and evidence](../../08-ai-compliance/03-control-mapping-and-evidence.md) and [audit readiness](../../08-ai-compliance/04-audit-readiness-and-ai-incidents.md).

Evidence examples from this chapter: the vetting audit log (hash-chained), SBOM per release, provenance and verification logs, DefectDojo SLA and MTTR reports, exception register, Scorecard results.

## 7. A 90-day starter plan

| Days | Goal |
|---|---|
| 0 to 30 | Inventory (SBOMs, lockfiles), pin CI actions by SHA, secret scanning, define SLAs and exception rules, stand up DefectDojo |
| 31 to 60 | Intake form and gate for new dependencies; registry mirror; dependency review on PRs; cooldown for updates |
| 61 to 90 | Provenance at L1 everywhere and L2 for released artifacts; verify at deploy; KPI dashboard; first tabletop ("poisoned dependency") |

## 8. Scenarios

1. **Board asks "are we exposed to the latest npm worm?"** Use the inventory to list affected versions in 1 hour; rotate tokens and secrets; block versions in the mirror; report counts. KPI: time to answer.
2. **Team wants a 6-month exception on a High.** Ask for compensating controls, a different approver, a 90-day expiry with review; if it is KEV-listed, escalate to the exception board.
3. **Auditor asks for proof the vetting process works.** Provide the audit log with its hash-chain verification, a sample of conditional decisions and their follow-up, and the SLA report.

## 9. Common mistakes

- Policy without owners and numbers.
- Exceptions without expiry, or approved by the requester's own manager chain only.
- KPIs that count findings, not fixes.
- Separate evidence for every audit instead of a shared mapping.
- Ignoring regulatory dates (CRA reporting from 11 Sept 2026).

## 10. Interview Q&A

<details><summary><b>Q1. Which KPIs would you show a CISO?</b></summary>
SLA compliance and MTTR by severity, overdue criticals, active exceptions and their age, SBOM and provenance coverage, and time to answer "do we use X?". Trends, not raw finding counts.
</details>

<details><summary><b>Q2. How should risk acceptance work?</b></summary>
Written justification, compensating controls, an approver different from the owner, a mandatory expiry, no silent renewal, and no acceptance for known-exploited vulnerabilities without an exception board. Expired acceptances reactivate the finding without resetting its SLA clock.
</details>

<details><summary><b>Q3. What does the EU CRA mean for an open-source dependency policy?</b></summary>
Manufacturers of products with digital elements must exercise due diligence on integrated third-party components, document components (SBOM), handle vulnerabilities for the support period and report actively exploited ones (reporting duties from 11 Sept 2026; most obligations from 11 Dec 2027). So the intake and monitoring process becomes compliance evidence.
</details>

<details><summary><b>Q4. How does EO 14028 affect a software vendor?</b></summary>
Federal customers can require evidence of secure development (SSDF) through the CISA attestation form and may ask for SBOMs. Later actions, including EO 14306, adjusted parts of this, so check what the specific contract and current guidance require.
</details>

## 11. Checklist

- [ ] I can list ten roles and what each owns.
- [ ] I can state an SLA table and exception rules.
- [ ] I can name ten KPIs and their direction.
- [ ] I can explain EO 14028 and the CRA dates in hedged terms.

## 12. References

- EO 14028 (2021); OMB M-22-18, M-23-16; CISA Secure Software Development Attestation Form; EO 14306 (2025).
- Regulation (EU) 2024/2847 (Cyber Resilience Act); ENISA guidance.
- NIST SP 800-161 Rev.1, SP 800-218.
- DefectDojo docs: SLA configuration, risk acceptance, metrics.
- Next: [chapter README](README.md) for the coverage table and Q&As.
