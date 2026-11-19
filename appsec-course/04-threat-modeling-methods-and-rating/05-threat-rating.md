# Lesson 05: Threat Rating (DREAD, OWASP Risk Rating, Bug Bar, Rapid Risk Assessment)

**Syllabus items covered:** [CTMP 2] "Introduction to Threat Rating", "DREAD", "OWASP Risk Rating Methodology", "Bug Bar", "Rapid Risk Assessment", "Risk Rating with OWASP Risk Rating Methodology"; [CSC 4] "Threat Rating", "DREAD", "OWASP Risk Rating", "Threat rating using OWASP risk rating methodology".

**Time:** 2 hours. **Lab:** [threat-rating](labs/threat-rating/README.md).

> **DBA analogy.** You cannot tune every SQL statement; you sort by elapsed time and fix the top ones. Threat rating is the AWR "top SQL" report for threats.

## 1. Introduction to threat rating

A threat model produces many threats. Rating gives each a **severity** so the team fixes the right ones first and can justify accepting the rest. A good rating method is:

- **Repeatable:** two people get similar results.
- **Explainable:** the reason for the score is written down.
- **Separates likelihood and impact**, because the treatments differ.
- **Uses business context**, not only technical severity.

Rating is a step **after** finding threats ([lesson 01, section 2](01-security-requirements-and-diagramming.md#2-threat-modeling-vs-threat-rating)).

## 2. DREAD

Microsoft's early scheme. Score each threat 1-10 (some use 1-3) on five questions and average:

| Letter | Question |
|---|---|
| D Damage | How bad if exploited? |
| R Reproducibility | How reliably can it be repeated? |
| E Exploitability | How much skill or tooling is needed? |
| A Affected users | How many are affected? |
| D Discoverability | How easy is it to find? |

**Why it fell out of favour:** subjective (in the lab two raters score the same threat 8.2 HIGH and 3.6 LOW), not repeatable, discoverability rewards security by obscurity, likelihood and impact are mixed in one number. Microsoft moved away from it (verify their current guidance). Know it for the exam; do not choose it for a new programme. More in [devsecops ch03 lesson 01](../../devsecops-course/03-security-requirements-and-threat-modeling/01-threat-modeling-stride-dread-and-challenges.md#3-dread-and-why-it-fell-out-of-favour).

## 3. OWASP Risk Rating Methodology

A written, factor-based scheme. Score 16 factors from 0 to 9.

**Likelihood** = average of 8 factors:

| Threat agent | Vulnerability |
|---|---|
| Skill level | Ease of discovery |
| Motive | Ease of exploit |
| Opportunity | Awareness |
| Size (how many attackers) | Intrusion detection (would we notice?) |

**Impact** = average of 8 factors:

| Technical impact | Business impact |
|---|---|
| Loss of confidentiality | Financial damage |
| Loss of integrity | Reputation damage |
| Loss of availability | Non-compliance |
| Loss of accountability | Privacy violation |

If you do not know the business impact, OWASP says to use technical impact only. Then: **0 to <3 LOW, 3 to <6 MEDIUM, 6 to 9 HIGH**, and read the matrix:

| | Likelihood LOW | Likelihood MEDIUM | Likelihood HIGH |
|---|---|---|---|
| **Impact HIGH** | MEDIUM | HIGH | CRITICAL |
| **Impact MEDIUM** | LOW | MEDIUM | HIGH |
| **Impact LOW** | NOTE | LOW | MEDIUM |

The same method with an LLM example and a matrix SVG is in [CAISP ch5 lesson 05](../../caisp-course/ch5-threat-modeling-ai-systems/05-rating-and-managing-risks.md#3-an-example-risk-rating-methodology-owasp-risk-rating).

### 3.1 Worked example: risk rating with the OWASP Risk Rating Methodology

Threat: **predictable password reset token** (the vulnerable service in the [password-reset lab](labs/password-reset-threat-model/README.md)).

| Group | Scores | Average |
|---|---|---|
| Threat agent | skill 6, motive 7, opportunity 9 (no access needed), size 9 (anyone online) | 7.75 |
| Vulnerability | discovery 7, exploit 5, awareness 6, detection 8 (logged, not reviewed) | 6.5 |
| **Likelihood** | 57 / 8 | **7.125 HIGH** |
| Technical | confidentiality 6, integrity 5, availability 1, accountability 7 | 4.75 |
| Business | financial 3, reputation 5, non-compliance 5, privacy 7 | 5.0 |
| **Impact** | 39 / 8 | **4.875 MEDIUM** |
| **Severity** | HIGH likelihood, MEDIUM impact | **HIGH** |

After the fix (CSPRNG tokens, detection reviewed), the vulnerability factors drop to 1, 1, 4, 3: likelihood 5.0 MEDIUM, impact unchanged, severity **MEDIUM**. A fix lowers likelihood, not impact: the asset is just as valuable. The lab's `owasp_risk()` reproduces both numbers.

## 4. Bug bar

A **bug bar** is a fixed table, agreed in advance, that maps a type of security bug to a severity and a rule such as "Critical and Important must be fixed before release". It comes from the **Microsoft SDL** (published sample bug bars for clients and servers; verify current versions). It removes debate during release crunch: you classify, the table decides.

Simplified server-side example used in the lab:

| Effect | Condition | Severity |
|---|---|---|
| Elevation of privilege | remote, anonymous | Critical |
| Elevation of privilege | authenticated or local | Important |
| Information disclosure | sensitive data, remote | Important |
| Spoofing / tampering | remote | Important |
| Denial of service | persistent, remote anonymous | Important |
| Denial of service | temporary, remote | Moderate |
| Any | requires victim interaction | one level lower |

Use a bug bar for **vulnerabilities and bugs** at release gates; use OWASP Risk Rating or a matrix for **design threats** and the risk register.

## 5. Rapid Risk Assessment

Mozilla's **Rapid Risk Assessment (RRA)** is a 30 to 60 minute structured interview with the service owner, designed for speed (verify the current Mozilla guide). Outputs:

- **Data dictionary:** what data the service handles and its classification (public, internal, confidential, restricted).
- **Threat scenarios** with impact rated separately for **confidentiality, integrity and availability** (LOW, MEDIUM, HIGH, MAXIMUM), and likelihood.
- **Recommendations** with owners.

The lab's RRA check catches a common mistake: a scenario that exposes CONFIDENTIAL data but is rated MEDIUM for confidentiality. RRAs fit Agile well: one per new service, refreshed on big changes.

## 6. Other scales you will meet

- **CVSS v4.0** (FIRST, November 2023): severity of a single vulnerability (base, threat, environmental, supplemental metrics). Not a risk score on its own.
- **EPSS:** probability that a CVE is exploited soon; useful for vulnerability prioritisation.
- **Qualitative 5x5 matrix:** used in risk registers ([chapter 03 risk-register lab](../03-risk-management-and-threat-modeling-overview/labs/risk-register/README.md)).
- **FAIR:** quantitative, in money.

## 7. Choosing a method

| Need | Use |
|---|---|
| Design threats in a threat model | OWASP Risk Rating or a calibrated likelihood x impact matrix |
| Release gate for security bugs | Bug bar |
| New service, little time | Rapid Risk Assessment |
| Third-party CVEs | CVSS + EPSS + KEV + your exposure |
| Exam question about DREAD | Explain it, then explain why it is not used |

## 8. Scenario: the 4.6-point argument

Two senior engineers rated the same threat with DREAD: 8.2 and 3.6. The meeting spent 40 minutes arguing. The team switched to OWASP Risk Rating with written factor definitions; disagreements now happen per factor ("is detection really 8? do we review these logs?"), which is a useful conversation, and results differ by less than one level.

## 9. Common mistakes

- Rating before the threat is clearly described.
- Using CVSS base scores as business risk.
- Forgetting that controls lower likelihood more often than impact.
- No record of *why* a factor got its score.
