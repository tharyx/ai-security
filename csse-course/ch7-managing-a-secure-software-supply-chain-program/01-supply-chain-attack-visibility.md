# Lesson 01: Problems with Current Supply Chain Attack Visibility

> **Chapter:** 7 · Managing a Secure Software Supply Chain Program · **Time:** ~3 hours
> **You will:** explain why vulnerability scanning sees only *known* problems, list the controls that can catch *unknown* ones, and use xz-utils and Shai-Hulud as worked examples.

| | |
|---|---|
| **Prerequisites** | [CAISP third-party vulnerabilities](../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md); a basic idea of SBOM and SCA |
| **Labs** | [oss-vetting-process](labs/oss-vetting-process/README.md) (malicious-heuristics stub), [slsa-level-2](labs/slsa-level-2/README.md) (provenance catches a swapped artifact) |
| **Syllabus lines** | Problems with current Supply Chain Attack Visibility · Detection of only known vulnerabilities · Detection of unknown vulnerabilities |
| **Diagram** | [known vs unknown](../../images/csse-ch7-known-vs-unknown.svg) |

> **Hedge.** Incident numbers change as researchers publish more data. Treat every count as "reported, verify at source".

## Why this matters

- **Equifax (2017):** a *known* flaw (Apache Struts CVE-2017-5638) had a patch available for weeks before the breach. About 147 million people were affected. A known-vulnerability problem: the signal existed, the process failed.
- **xz-utils (CVE-2024-3094, Mar 2024):** a backdoor planted over a long social-engineering campaign against one maintainer. There was **no CVE when it shipped**. It was found by a developer who noticed odd SSH login latency.
- **tj-actions/changed-files (CVE-2025-30066, Mar 2025):** a widely used GitHub Action had its mutable tags repointed to code that printed CI secrets into logs. Pipelines that referenced a tag pulled it automatically.
- **Shai-Hulud (Sept 2025, and later waves):** a self-spreading npm worm that stole tokens and secrets and republished trojanized versions of the victims' own packages. Reported waves hit hundreds of packages and thousands of repositories (counts vary).

Each of the last three was **unknown at the moment of installation**. A scanner that only matches against advisories could not warn you.

## 1. The visibility problem in one picture

You cannot defend what you cannot see, and "seeing" has two different meanings:

| | Known problems | Unknown problems |
|---|---|---|
| What exists | A CVE, advisory, or malware report | Nothing public yet |
| Question | "Do I run a component that is on a list?" | "Does this component or build behave in a way it should not?" |
| Needs | Inventory (SBOM) plus a database | Behaviour, provenance, comparison, anomaly detection |
| Failure mode | You find out late, or never act | You find out after compromise, or by luck |

A clean scan means "no *known* issue". It never means "safe".

## 2. Detection of only known vulnerabilities

### 2.1 How it works

```text
inventory (SBOM / lockfile / image layers)  ->  match name+version against databases  ->  report
databases: NVD, OSV, GitHub Advisory Database, vendor feeds; ranking: CVSS, EPSS, CISA KEV
```

Tools: Trivy, Grype, OSV-Scanner, Dependabot, Snyk, and SCA features in GitLab and GitHub. Image scanners work the same way on OS packages.

### 2.2 Why it is not enough

| Gap | Effect |
|---|---|
| **Disclosure lag** | An attack can run for days or months before a record exists |
| **Malicious packages are not "vulnerabilities"** | A typosquat has no CVE; it is malware by design. Malware feeds exist (for example OSV's malicious-package advisories) but only list what someone already found |
| **Matching errors** | Wrong package names, missing CPEs, vendored or renamed code, statically linked libraries, no lockfile = false negatives |
| **Reachability** | The CVE may be in code you never call, so alert volume hides the real risks |
| **Backdoors in trusted code** | Real maintainer, real signature, real release: all checks pass |
| **Build-time changes** | The source repo is clean, but the release tarball or binary differs from it |

### 2.3 Making the known side good

Known-problem management is still the foundation. Do these well before buying anything exotic: complete inventory, scan on every build **and** continuously (new CVEs appear after you ship), prioritize with KEV and EPSS (see [cybersecurity-track 08](../../cybersecurity-track/08-vulnerability-management/03-scoring-and-prioritization.md)), set SLAs ([lesson 05](05-program-management.md)), and track everything in one hub ([DefectDojo lab](labs/defectdojo-basics/README.md)).

## 3. Detection of unknown vulnerabilities

You rarely *detect* the unknown directly. You use controls that either **raise the chance of noticing** or **shrink the damage**.

| Control family | What it looks at | Catches | Example tools and ideas |
|---|---|---|---|
| **Behavioural analysis** | What a package does on install or run: network calls, new processes, file writes, env-var reads | Droppers, credential stealers, worms | Sandboxed install analysis; runtime sensors; egress allowlists on CI |
| **Malicious-package heuristics** | Static signals in package code and metadata: obfuscation, install scripts, suspicious URLs, typosquat names, new maintainers | Many commodity malware packages | GuardDog (Datadog), Socket-style services, registry-side scanners (lab: [vetting stub](labs/oss-vetting-process/README.md)) |
| **Release diffing** | What changed between version N and N+1; unusual diffs in a "patch" release | Injected code, new install hooks | Manual review for critical deps; diff tools; deps.dev comparisons |
| **Provenance** | Was this artifact built from that source, by that builder? | Tampered binaries, artifacts uploaded by hand, stolen-token publishes | SLSA provenance, npm/PyPI trusted publishing and attestations, Sigstore ([labs](labs/slsa-level-2/README.md)) |
| **Reproducible builds** | Can an independent party rebuild the same bits? | Build-time injection (xz-style tarball tricks, compromised builders) | Reproducible Builds project; Debian/Nix efforts; bit-for-bit comparison |
| **Maintainer and ownership signals** | New maintainer, ownership transfer, sudden activity, 2FA status | Account takeover and long-con handovers (event-stream, xz) | Scorecard checks, registry metadata, [vetting engine](labs/oss-vetting-process/README.md) |
| **Time and containment** | Not detecting, but delaying and limiting | Fast-moving worms and poisoned releases | Cooldown before adopting new versions; least-privilege CI tokens; short-lived credentials |

### 3.1 Cooldown, the cheap one

Most malicious releases are discovered and pulled within hours or days. A **cooldown** (do not adopt a version until it is a few days old) lets the community find it first. Several tools offer this (for example Renovate's release-age setting, Dependabot cooldown, and a minimum release age option in newer pnpm; verify names and defaults in your tool's docs). Make exceptions only for security fixes, after review.

### 3.2 Why provenance and reproducibility matter

Provenance cannot tell you "this code is good". It tells you "this artifact came from this source by this process". That alone breaks whole classes of attack: a token thief publishing a package by hand from a laptop has **no provenance** from your trusted builder, so a consumer policy "require provenance from the expected workflow" rejects it. See [SLSA lab 2](labs/slsa-level-2/README.md).

## 4. Worked examples

### 4.1 xz-utils (Mar 2024)

| Question | Answer |
|---|---|
| What happened | A contributor built trust over about two years, gained maintainer rights, and inserted an obfuscated backdoor that targeted sshd on some Linux distributions via liblzma. |
| Why scanners missed it | No CVE; signed releases from a legitimate maintainer; the malicious build steps lived in release tarballs, not visibly in the git tree. |
| How it was found | A developer investigating a small CPU and latency anomaly in SSH logins. Luck plus curiosity. |
| What would have helped | Comparing release tarballs with the git source (reproducibility); fewer dependencies loaded into sshd; ownership and maintainer-change signals; funding and a second maintainer for critical projects. |

### 4.2 Shai-Hulud and its successors (2025 to 2026)

| Question | Answer |
|---|---|
| What happened | Malware in an npm package ran at install, searched the machine and CI for secrets, used stolen npm tokens to publish infected versions of the victim's other packages, and leaked secrets to public GitHub repositories. A second wave (Nov 2025) was larger. Reports in 2026 describe spread across npm and PyPI. Hedge all numbers. |
| Why scanners missed it | Brand-new versions of trusted packages; no advisory for hours. |
| What helped | Cooldown; blocking install scripts by default; trusted publishing with short-lived OIDC credentials instead of long-lived tokens; 2FA that cannot be phished; secret scanning; egress filtering in CI. |

**Common lesson:** detection of the unknown is partial. Layer **exposure reduction** (pin, cool down, least privilege) with **verification** (provenance) and **fast response** (inventory so you can answer "do we run it?" in minutes).

## 5. Defend it: a layered view

| Layer | Control | Type |
|---|---|---|
| Know | SBOM per build, lockfiles, runtime inventory | Process + Hard |
| Match | SCA with KEV/EPSS, daily rescans | Hard |
| Gate | Vetting intake ([lesson 02](02-vetting-process-and-automation.md)), allowlisted registries | Hard |
| Verify | Provenance and signature policy at deploy ([lab](labs/slsa-level-2/README.md)) | Hard |
| Delay | Cooldown for new versions | Soft/Hard |
| Contain | No long-lived tokens in CI, egress control, no install scripts by default | Hard |
| Respond | Playbook: "is X in our estate?" in under an hour | Process |

**What does NOT work on its own:** "we run Trivy", "we use only popular packages" (popular packages are the worm's targets), "we trust signed packages" (signing proves who, not what).

## 6. Hands-on

- Run the [vetting demo](labs/oss-vetting-process/README.md) and note which cases the *heuristics* caught that a CVE database would have missed (`reqeusts`).
- Run [slsa-level-2](labs/slsa-level-2/README.md): swap the artifact and see that the digest check catches it with no CVE database at all.
- Optional, real tools in your course lab: scan a sample repo with Trivy or OSV-Scanner, then run GuardDog on a package. Compare what each reports (hedged; check the tools' docs).

## 7. Scenarios

1. **Clean scan, still breached.** A scan on Friday is clean; on Monday a maintainer's token is stolen and a bad version is published. *Investigate:* when did the lockfile change, was the version less than 3 days old, did the build run install scripts? *Fix:* cooldown, lockfile-only installs in CI, no scripts, egress block, rotate secrets.
2. **A new CVE in a base image.** *Investigate:* the SBOM stored at build time answers "where is it deployed" in minutes. *Fix:* rebuild and redeploy, track in DefectDojo against SLA.
3. **A tool says "0 vulnerabilities".** *Investigate:* Was a lockfile present? Is the scanner's database fresh? Was vendored code scanned? *Fix:* treat "0" as "nothing known in what I could see".

## 8. Common mistakes

- Treating the scanner's result as a safety certificate.
- Scanning only at build time and never rescanning deployed artifacts.
- Optimizing for CVSS count rather than exploitability and exposure.
- Trusting a package because it is popular or signed.
- No inventory, so the incident response question "do we use it?" takes days.

## 9. Interview Q&A

<details><summary><b>Q1. Why can SCA never be your only supply chain control?</b></summary>
It matches inventory against what is already known. Malicious packages, backdoors in trusted code, and brand-new attacks have no advisory yet. Add behaviour and heuristic analysis, provenance, cooldown and containment.
</details>

<details><summary><b>Q2. How would provenance have helped against a stolen npm token?</b></summary>
A thief publishes from their own machine, so the package has no attestation from your trusted CI workflow. A consumer policy that requires provenance from the expected builder and repo rejects it.
</details>

<details><summary><b>Q3. What does a reproducible build give you?</b></summary>
An independent party can rebuild from source and compare bits. A difference between the published artifact and the rebuild reveals build-time tampering such as an injected step, even when the source looks clean.
</details>

<details><summary><b>Q4. Explain the value of a dependency cooldown.</b></summary>
Malicious versions are usually caught quickly. Waiting a few days before adoption lets others find them first. It costs a small delay for non-urgent updates and is cheap compared with detection tooling.
</details>

## 10. Checklist

- [ ] I can state what "known" and "unknown" mean for supply chain threats.
- [ ] I can name five controls for unknown threats and what each catches.
- [ ] I can explain xz-utils and Shai-Hulud in four sentences each, with hedged numbers.

## 11. References

- OSV (osv.dev) and OSV-Scanner; GitHub Advisory Database; CISA KEV catalog; FIRST EPSS.
- GuardDog (Datadog) project page; Reproducible Builds (reproducible-builds.org).
- xz-utils backdoor: public disclosure on the oss-security mailing list (29 Mar 2024) and CVE-2024-3094.
- Equifax: US GAO and House Oversight reports (2018 to 2019).
- Next: [Lesson 02: vetting and automation](02-vetting-process-and-automation.md).
