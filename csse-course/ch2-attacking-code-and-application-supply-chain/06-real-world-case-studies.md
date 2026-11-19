# Lesson 06: Real-World Case Studies of Code Supply Chain Attacks

> **Chapter:** 2 · Attacking Code and Application Supply Chain · **Time:** ~4 hours
> **You will:** tell four case-study patterns step by step (environment-variable theft, exposed private source, leaked proprietary source, stolen signing certificates), with the lesson and the control for each.

| | |
|---|---|
| **Prerequisites** | Lessons [02](02-attacks-on-scm-systems.md), [03](03-supply-chain-attacks-on-package-managers.md) and [04](04-attacks-on-build-and-cicd-systems.md) |
| **Labs** | [codecov-attack](labs/codecov-attack/README.md) |
| **Syllabus lines** | Real-World case studies of code supply chain attack · Stealing environment variables from build servers · Exposing private source code on GitHub · Leaking source code of patented technologies · Stolen code-sign certificates or signed malicious apps |

> **Safety.** Facts are from public reporting and **may be incomplete or revised: verify at the primary sources** listed in each case. Numbers are hedged. No exploit steps are given.

## Why this matters

Case studies train you to ask the right question: **which trust decision failed, and which cheap control would have stopped it?** In most cases below it was a missing verification, an over-privileged secret or an unprotected key.

## 1. Stealing environment variables from build servers (the Codecov pattern)

**What happened (hedged).** Codecov provides code-coverage tooling. Customers' CI jobs commonly ran a **Bash Uploader** script fetched from Codecov's servers. From **January to April 2021**, an attacker had changed that script so it also **sent the CI job's environment variables** (tokens, keys, credentials, repo info) to an attacker-controlled server. Codecov's disclosure said the attacker extracted credentials from an error in its **Docker image creation process** and used them to alter the script. It was found in **April 2021** after a customer noticed that the script's checksum did not match the one published on GitHub. Customers were told to rotate secrets that were exposed to the CI job.

**Why it worked.**

1. The pipelines **downloaded and ran a script** on every build, trusting the server.
2. The CI environment held **many secrets**, available to every step.
3. The runners had **open internet egress**.
4. Detection came late: nobody compared the script to a known-good hash.

**Controls (tested in the lab).**

| Control | Where |
|---|---|
| Verify a checksum or **signature** (from a different channel) before running a downloaded script | [codecov-attack lab](labs/codecov-attack/README.md) |
| Minimal environment: pass only the variables a step needs | same lab |
| Egress allowlist for runners | same lab |
| Prefer pinned, vendored or package-managed tools over `curl \| bash` | [lesson 07](07-best-practices-for-securing-the-application-supply-chain.md) |
| Short-lived credentials (OIDC), secret scoping, rotation after incident | [lesson 04](04-attacks-on-build-and-cicd-systems.md) |

**Echoes.** The tj-actions/changed-files incident (2025) and the Shai-Hulud npm worm (September 2025, which stole tokens and pushed them to public GitHub repos; verify counts) have the same goal: **CI and developer secrets**.

**Sources.** Codecov's April 2021 security update; the incident write-ups from the companies that responded (verify at the sources).

## 2. Exposing private source code on GitHub

**Patterns (generic, hedged).** Private code and secrets reach the public in a few repeatable ways:

| Pattern | How |
|---|---|
| **Repo made public by mistake** | A click or a default setting; a private fork turned public; a mirror pushed to a public remote. |
| **Personal public repos** | An employee or contractor pushes work code to their personal account. Reported cases include credentials left in a public repository by a contractor for years (a 2022 car-maker disclosure; verify). |
| **Secrets in history** | Keys committed once, repository later opened, or a copy kept in a fork ([lesson 02](02-attacks-on-scm-systems.md)). |
| **Stolen access tokens** | An attacker uses a stolen token to clone **private** repos, then publishes or sells the code. Several 2022 extortion cases (the Lapsus$ group) involved source-code theft from large companies; verify. |
| **Malware that publishes secrets** | The Shai-Hulud worm (2025) pushed harvested secrets into **public repositories** created in victims' accounts (verify scale; reports vary). |
| **CI logs and artifacts** | Public build logs show secrets or source. |

**Why it hurts.** Exposed code shows internal design, hardcoded secrets, API endpoints and bugs. Attackers read it for vulnerabilities and credentials. Even after takedown, copies and forks may remain.

**Response (in order).** (1) **Rotate** every secret found in the code and history; (2) remove public access and request takedowns of copies (for example through the platform's DMCA process); (3) review logs for use of those secrets; (4) assess what the code reveals (vulnerabilities, customer data); (5) legal and customer notification as required; (6) fix the root cause.

**Prevent.** Organization policy that restricts creating public repos; secret scanning with **push protection**; audit logs and alerts when visibility changes; short-lived tokens; MFA and SSO; DLP and monitoring for company code on public hosts (search for internal package or domain names); contractor access via managed accounts.

## 3. Leaking source code of patented technologies

**Why this is its own case.** For companies whose value is **proprietary technology** (chip designs, firmware, drivers, algorithms), source code is a trade secret and sometimes covered by patents and licenses. A leak has three kinds of damage: **competitive** (others copy), **security** (bugs and keys become visible), and **legal** (trade-secret protection can weaken, contracts and licenses are breached).

**Public examples (hedged; verify).** In 2022 the Lapsus$ group claimed and published large amounts of source from several major technology companies (for example NVIDIA, Samsung and Microsoft cases were widely reported). Chip and firmware vendors have also seen internal source or build keys leak through third parties (for example the 2023 MSI incident in the next section). Treat the claims as reported, not proven, and use generic lessons.

**Typical paths (generic):** a compromised developer account or VPN; an insider or contractor copying a repo; an exposed internal Git server or backup; a third-party vendor with repo access; CI artifacts and caches; a misconfigured object-storage bucket.

**Controls:**

| Control | Note |
|---|---|
| Least privilege and **need-to-know** for sensitive repos; separate crown-jewel repos | smaller blast radius |
| SSO with MFA and device posture for source access | stops simple token theft |
| **Download and clone monitoring**, anomaly alerts for bulk clones | detects exfiltration |
| **Canary tokens and honey files** in repos | alerts when someone reads them |
| Segregate build and signing secrets from source | a source leak should not give signing keys |
| Watermark or trace sensitive builds; legal tools (contracts, DMCA takedowns) | deterrence and response |
| Vendor access reviews | third parties are part of your chain |

**After a leak:** assume attackers will **audit the code for vulnerabilities** and use leaked keys; rotate secrets and certificates, increase monitoring, patch quickly, and prepare coordinated communication.

## 4. Stolen code-sign certificates or signed malicious apps

**Why attackers want signing keys.** Operating systems, EDR and users trust software signed by known vendors. A **validly signed** malicious binary bypasses many "unsigned code" checks.

| Case (hedged; verify) | What was reported | Lesson |
|---|---|---|
| **Stuxnet (2010)** | Used drivers signed with certificates reportedly stolen from other companies | An early, famous example |
| **SolarWinds (2020)** | The trojanized update was signed with SolarWinds' own legitimate certificate, because the code was injected **before** signing | A signature proves the build step ran, not that the code is clean |
| **NVIDIA (2022)** | The Lapsus$ group published stolen data that included two code-signing certificates (reported as expired), and malware was later seen signed with them, because systems could still accept them for some drivers | Expired is not always unusable; revoke and tighten policy |
| **MSI (2023)** | The Money Message extortion group leaked MSI data that was reported to include **firmware signing keys** (and Intel Boot Guard keys of devices), raising risk of malicious signed firmware | Firmware keys are a long-lived risk |
| **3CX (2023)** | A trojanized desktop app was **validly signed**; the attack cascaded from an earlier compromised trading software | A signed update from a trusted vendor can still be malicious |

**Defend.**

1. **Protect keys in hardware or a managed signing service** (HSM, cloud KMS, managed signing services). Industry rules for public code-signing certificates have been tightening (hardware key storage from 2023; validity periods are being shortened; verify the current CA/Browser Forum baseline).
2. **Separate signing from the build** and require the signing service to **verify** what it signs (provenance, policy, approvals), not just "a pipeline asked".
3. **Short-lived certificates and keyless signing** (for example Sigstore for open-source artifacts) reduce the value of a stolen key.
4. **Different keys per product and environment**, so one leak is bounded.
5. **Monitor for misuse**: scan public malware feeds for binaries signed with your certificates; have a **revocation and re-signing plan**; use timestamping policies.
6. **Verify on the consuming side**: do not treat "signed" as "safe"; check the **signer identity** you expect, plus provenance and your own scans.

Link to labs: [git-commit-signing](labs/git-commit-signing/README.md) (signature verification against an allowed signer list), and [CMCPSE sign/verify](../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build/).

## Hands-on

1. Re-run the [Codecov lab](labs/codecov-attack/README.md) and write, in one sentence each, which control would have stopped the attack first, and which would have limited damage.
2. For one case in this lesson, fill a table: trust decision that failed, cheap control, detection signal.

## Real-world scenarios

1. **A vendor's tool in your CI was reported compromised.** First hour: list what secrets that job could see, rotate them in order of power, review logs for their use, pin or remove the tool, and tell stakeholders.
2. **A contractor's repo with your code is public.** Rotate secrets, request takedown, check access logs, assess exposure, fix contracts and policy.
3. **Your company's certificate appears on a malware sample.** Revoke, notify the CA and vendors, rebuild trust (new key in hardware), investigate how the key was reached.

## Common mistakes

- Rotating only the secret you found first.
- Believing that deleting a repo removes the copies.
- Storing signing keys on the build server.
- Treating a valid signature as proof of benign code.

## Interview preparation

<details><summary><b>Q1. Summarize the Codecov attack and the two cheapest controls.</b></summary>
The hosted Bash Uploader script was modified (Jan to Apr 2021) so CI jobs that ran it sent environment variables to an attacker server; found when a customer saw a hash mismatch. Cheapest controls: verify a checksum or signature before running a downloaded script, and give jobs a minimal environment (plus egress control and rotation).
</details>

<details><summary><b>Q2. A secret was in a public repo for an hour. What do you do?</b></summary>
Treat it as compromised: rotate it, review logs for use, remove it from history and any copies, find how it got there, and add push protection and secret scanning. Removing it from the repo alone is not enough.
</details>

<details><summary><b>Q3. Why can signed malware happen, and how do you reduce the risk?</b></summary>
Keys can be stolen, or malicious code can be injected before signing (SolarWinds). Use hardware-protected or managed keys, short-lived and per-product keys, a signing service that verifies provenance, monitoring for misuse, and revocation plans. Consumers should verify signer identity and provenance, not only "signed".
</details>

<details><summary><b>Q4. What do you do after proprietary source code leaks?</b></summary>
Rotate secrets and keys found in it, expect attackers to hunt for vulnerabilities in it and patch fast, increase monitoring, pursue takedowns and legal steps, review how access was gained, and communicate carefully.
</details>

## Checklist (definition of done)

- [ ] I can tell the Codecov story with hedged dates and say what failed.
- [ ] I can list the response steps for an exposed repo.
- [ ] I can explain why SolarWinds shows that signing is not enough.

## References

- Codecov security update (April 2021): <https://about.codecov.io/security-update/>
- NVIDIA and MSI reporting (2022, 2023) from security vendors and news outlets: verify with primary statements.
- SolarWinds and CISA advisories on SUNBURST: <https://www.cisa.gov/>
- CA/Browser Forum code-signing baseline requirements: <https://cabforum.org/>
- Sigstore: <https://www.sigstore.dev/>
