# Chapter 04: Software Component Analysis (SCA) in the CI/CD Pipeline

This chapter covers **third-party component risk**: what SCA is, why it is hard (transitive dependencies, false positives, reachability), how to choose a tool, and how to embed it in a pipeline with break-the-build thresholds. Three labs run **offline twins** of RetireJS, npm audit, Safety and OWASP Dependency-Check, using fixture lock files and one shared **local advisory database in OSV format**. **Node, Python packages, Java, Maven and the network are not needed.**

> **Safety.** Every package name, version and advisory id (`DSO-OSV-nnnn`) is fictional. Nothing is installed, downloaded or executed. Scan only projects you own.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CDP 4] Software Component Analysis (SCA) in CI/CD pipeline | [Lesson 01](01-software-component-analysis-basics.md), [Lesson 02](02-sca-tools-in-the-pipeline.md) | all three labs |
| [CDP 4] What is Software Component Analysis. | [01 section 1](01-software-component-analysis-basics.md#1-what-is-sca) (SVG); repo [CSE ch2 sca lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca/README.md) | [retirejs-npm-audit](labs/retirejs-npm-audit/README.md) |
| [CDP 4] Software Component Analysis and Its challenges. | [01 sections 2 and 3](01-software-component-analysis-basics.md#3-challenges-of-sca) (transitive dependencies, false positives, reachability) (SVG); repo [CAISP ch4 third-party-vulns](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/README.md), [typosquatting lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/typosquatting-dependency/README.md) | [safety-pip-python](labs/safety-pip-python/README.md), [dependency-check-java](labs/dependency-check-java/README.md) |
| [CDP 4] What to look in a SCA solution (Free or Commercial). | [01 section 4](01-software-component-analysis-basics.md#4-what-to-look-for-in-an-sca-solution-free-or-commercial) | n/a |
| [CDP 4] Embedding SCA tools like OWASP Dependency Checker, Safety, RetireJs and NPM Audit, Snyk into the pipeline. | [Lesson 02](02-sca-tools-in-the-pipeline.md) (pip-audit and osv-scanner as current alternatives); [real-tools/dependency-check.md](real-tools/dependency-check.md), [real-tools/sca-cli-tools.md](real-tools/sca-cli-tools.md); repo [CSE ch2 sca-sast-pre-commit](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca-sast-pre-commit/README.md), [CSE ch6 Snyk lab](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/snyk-container-scan/README.md) | all three labs |
| [CDP 4] Hands-On Labs: | Labs below | [Lab index](#lab-index) |
| [CDP 4] using RetireJS and NPM to scan third party component vulnerabilities in Javascript Code Base. | [02 sections 1 and 3](02-sca-tools-in-the-pipeline.md#1-the-tools-and-when-to-use-each); [real-tools/sca-cli-tools.md](real-tools/sca-cli-tools.md) | [retirejs-npm-audit](labs/retirejs-npm-audit/README.md) |
| [CDP 4] using Safety/pip to scan third party component vulnerabilities in Python Code Base. | [02 section 1](02-sca-tools-in-the-pipeline.md#1-the-tools-and-when-to-use-each) (Safety, pip-audit) | [safety-pip-python](labs/safety-pip-python/README.md) |
| [CDP 4] Demo: | Demo below | [dependency-check-java](labs/dependency-check-java/README.md) |
| [CDP 4] Using OWASP Dependency Checker to scan third party component vulnerabilities in Java Code Base. | [02 sections 1 and 3](02-sca-tools-in-the-pipeline.md#3-break-the-build-thresholds); [real-tools/dependency-check.md](real-tools/dependency-check.md) | [dependency-check-java](labs/dependency-check-java/README.md) (demo level) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **OWASP Dependency Checker** | The name is **OWASP Dependency-Check**. It needs an **NVD API key** since the NVD API 2.0 changes, downloads a large database on first run, and CPE name matching causes false positives. Cache or mirror the database; keep a suppression file with reasons and expiries. |
| **Safety** | Free database has limits and licence terms; newer versions changed commands (`safety scan`) and may need an account. **pip-audit** (PyPA) and **osv-scanner** are current free alternatives. |
| **"Safety/pip"** | pip itself does not scan. The pip-based tool is **pip-audit**. |
| **RetireJS** | Still useful for front-end files that are **not** in npm (copied scripts, CDN bundles). Check the project's activity before depending on it. |
| **NPM Audit** | Built in to npm; uses GitHub advisories. Use `npm ci` first, `--omit=dev` for production, and check whether a fix is a breaking major. |
| **Snyk** | Commercial with a free tier; needs an account and token (keep it in CI secrets); data-handling terms apply. |
| "Software Component Analysis" | Also called **software composition analysis**. Related: **SBOM** (CycloneDX, SPDX) and **VEX** statements for "not affected". |
| CVSS as the only signal | Add exploitability data (EPSS, CISA KEV; verify) and **reachability** when you can. |

## Learning order

1. [Lesson 01](01-software-component-analysis-basics.md): SCA, challenges, tool checklist. About 1.5 hours.
2. [Lesson 02](02-sca-tools-in-the-pipeline.md) and the [tool guides](real-tools/sca-cli-tools.md). About 2 hours.
3. [retirejs-npm-audit](labs/retirejs-npm-audit/README.md), then [safety-pip-python](labs/safety-pip-python/README.md). About 2.5 hours.
4. [dependency-check-java](labs/dependency-check-java/README.md) with the [Dependency-Check guide](real-tools/dependency-check.md). About 1.5 hours.
5. Then [Chapter 05: Static Analysis and Secrets](../05-static-analysis-and-secrets/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest devsecops-course/04-software-component-analysis`. They share [labs/_shared](labs/_shared/osv_common.py) (OSV records, numeric version compare, ignores with expiry, gates).

| Lab | Course exercise | Tests |
|---|---|---|
| [retirejs-npm-audit](labs/retirejs-npm-audit/README.md) | RetireJS and NPM on a JavaScript code base | 11 |
| [safety-pip-python](labs/safety-pip-python/README.md) | Safety/pip on a Python code base | 10 |
| [dependency-check-java](labs/dependency-check-java/README.md) | Demo: OWASP Dependency Checker on a Java code base | 10 |

## How the three courses overlap here

- **CDP 4** owns this chapter.
- **CCSE** teaches SCA as part of the supply chain: [CSE ch2 sca](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca/README.md) (a lock-file scanner), [sca-sast-pre-commit](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca-sast-pre-commit/README.md), typosquatting and dependency confusion, and SBOM and Snyk/Trivy labs in [CSE ch6](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/README.md). This chapter adds the **named tools**, ecosystem-specific behaviour and the pipeline thresholds, and links back instead of repeating SBOM and malicious-package material.
- **CDE** has no separate SCA chapter; container image scanning with Trivy is in [chapter 11](../11-defending-containers-at-scale/README.md), and tracking findings is in [chapter 14](../14-vulnerability-management/README.md).
- **CAISP** covers third-party vulnerabilities in AI projects: [ch4 third-party-vulns](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/README.md).

## Exam tips

- **SCA finds known flaws in third-party code.** Not your code (SAST) and not unknown flaws.
- **Transitive dependencies** are the usual blind spot; show the path and fix the direct parent.
- **Name matching versus coordinate matching:** CPE (NVD, Dependency-Check) gives more false positives; OSV and GitHub advisories use package coordinates.
- **Reachability lowers urgency, it does not remove the finding.**
- **Break-the-build options:** severity floor, CVSS score, count cap, new-only, fixable-only, confidence floor, production scope.
- **Suppressions need a reason, an owner and an expiry.**
- **Rescan on a schedule.** New CVEs appear after release.
- **Know the current alternatives:** pip-audit and osv-scanner for Python and many ecosystems; Dependabot or Renovate for fixes.
- **Dependency-Check needs an NVD API key** and a cached database in CI.

## 15 exam-style questions

<details>
<summary>1. What is SCA and how does it differ from SAST and DAST?</summary>

SCA inventories third-party components and matches them to known vulnerabilities. SAST analyses your own source code; DAST tests the running application. SCA cannot find unknown flaws or bugs in your code.
</details>

<details>
<summary>2. Why are transitive dependencies a problem?</summary>

You did not choose them, they can be many levels deep, and the vulnerable library may be reached only through a parent you cannot easily change. Show the path, bump the direct parent, or pin or override the transitive version.
</details>

<details>
<summary>3. What is an SBOM and how does it help SCA?</summary>

A software bill of materials lists the components in a build (CycloneDX or SPDX). Scanning the stored SBOM lets you check new CVEs against past releases without rebuilding.
</details>

<details>
<summary>4. Why does Dependency-Check give false positives?</summary>

It matches by guessed CPE vendor and product names. A different artifact with a similar name (for example a docs or test-utils jar) can match a CVE for the main library. Confidence levels, scope filters and suppressions manage this.
</details>

<details>
<summary>5. What does Dependency-Check need to run well today?</summary>

An NVD API key (since NVD API 2.0), a cached or mirrored database so each CI run does not re-download everything, and a maintained suppression file. Verify details at source.
</details>

<details>
<summary>6. What can RetireJS find that npm audit cannot?</summary>

JavaScript libraries that are not managed by npm: files copied into the repository, CDN bundles and renamed files, recognised by file name, content banner or hash.
</details>

<details>
<summary>7. What does `npm audit --omit=dev` do and why use it?</summary>

It ignores dev dependencies, so only what ships to production counts. Dev-only findings still matter for the build machine, so track them with a lower priority.
</details>

<details>
<summary>8. Safety versus pip-audit: what should you say in an interview?</summary>

Safety is the older commercial-backed tool with a free database that has limits and licence terms and changed its commands over time. pip-audit (PyPA) uses PyPI and OSV data and is a current free alternative. Both need pinned requirements for reliable results.
</details>

<details>
<summary>9. What is reachability analysis?</summary>

Checking whether the vulnerable function is actually called by your code (or whether attacker data reaches it). Unreachable findings are lower priority. It is a heuristic and does not replace upgrading.
</details>

<details>
<summary>10. List four break-the-build rules for SCA.</summary>

Severity floor (high and above); CVSS threshold (for example 7.0); count cap during a legacy clean-up; new findings only against a baseline; fixable findings only; confidence floor; production scope only.
</details>

<details>
<summary>11. What makes a good suppression?</summary>

A specific finding id and package, a written reason (for example "false positive" or "not reachable"), an owner, and an expiry date, so it is reviewed again. Expired suppressions must reactivate the finding.
</details>

<details>
<summary>12. How do you compare versions correctly?</summary>

Numerically by segments, not as strings: 1.10.0 is newer than 1.9.0. Handle pre-release tags (2.0.0-rc1 is older than 2.0.0) and the OSV ranges `introduced`, `fixed` and `last_affected`.
</details>

<details>
<summary>13. How often should you run SCA?</summary>

On every pull request for fast feedback, on release builds to produce an SBOM, and on a schedule (nightly or weekly) because new advisories appear after you ship.
</details>

<details>
<summary>14. A critical CVE appears in a transitive dependency with no fix available. What do you do?</summary>

Check reachability and exposure, apply mitigations (config, WAF, disabling the feature), look for an override or an alternative library, record an accepted risk with an expiry, and watch for the fix. Do not silently ignore it.
</details>

<details>
<summary>15. Name five things to check when choosing an SCA tool.</summary>

Language and package manager coverage, lock-file and transitive support, database quality and update speed, matching method and false-positive rate, reachability data, policy and suppression workflow, CI integration and SARIF/SBOM support, licence and cost, privacy of uploaded manifests, and maintenance activity.
</details>

## References

- OWASP Dependency-Check, npm audit, RetireJS, Safety, pip-audit, osv-scanner, Snyk, Dependabot and Renovate documentation (verify current versions).
- OSV schema (ossf.github.io/osv-schema); NVD (nvd.nist.gov); GitHub Advisory Database; FIRST EPSS; CISA KEV.
- CycloneDX and SPDX specifications.
- Repo: [CSE ch2](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md), [CSE ch6](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/README.md), [CAISP ch4](../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md).
