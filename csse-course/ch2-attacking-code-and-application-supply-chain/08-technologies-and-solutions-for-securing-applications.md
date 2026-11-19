# Lesson 08: Technologies and Solutions for Securing Applications

> **Chapter:** 2 · Attacking Code and Application Supply Chain · **Time:** ~5 hours
> **You will:** explain SCA, SAST, DAST and fuzz testing, what each finds and misses, how to wire them into pre-commit and CI, and how to handle false positives.

| | |
|---|---|
| **Prerequisites** | [Lesson 05](05-attacks-on-the-application-side.md), [lesson 07](07-best-practices-for-securing-the-application-supply-chain.md) |
| **Labs** | [sca](labs/sca/README.md) · [sast](labs/sast/README.md) · [dynamic-analysis](labs/dynamic-analysis/README.md) · [sca-sast-pre-commit](labs/sca-sast-pre-commit/README.md) · [pre-commit-hooks](labs/pre-commit-hooks/README.md) |
| **Related** | [CAISP ch4 third-party-vulns](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/third-party-vulns/) · [CAISP ch4 ai-code-weaknesses](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/) · [CMCPSE ch5 sast-vulnerable-mcp-server](../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/README.md) · [fuzz-mcp-tools](../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/fuzz-mcp-tools/README.md) · [vulnerability prioritization](../../cybersecurity-track/08-vulnerability-management/README.md) |
| **Syllabus lines** | Technologies and solutions for securing applications · SCA · SAST · DAST · Fuzz Testing |

> **Safety.** The labs run offline or on `127.0.0.1` with fake data. Scan only systems you own or may test. Tool features and licenses change: **verify at the source**.

## Why this matters

Findings are cheaper to fix the earlier they appear. Each technique sees a different slice, so you need several, placed at the right points in the workflow.

| | SCA | SAST | DAST | Fuzzing |
|---|---|---|---|---|
| Looks at | dependencies (lock files, SBOM, images) | your source code | the running app from outside | the program with many random or mutated inputs |
| Finds | known vulnerable components, licenses | patterns and data flows: injection, secrets, weak crypto | runtime issues: XSS, SQLi, SSRF, misconfig, headers | crashes, memory errors, hangs, logic bugs on parsing code |
| Misses | unknown (0-day) bugs, your own code | runtime config, business logic; noisy | code not reached by the crawler, logic flaws, behind-login without setup | deep logic, anything the harness does not reach |
| When | commit, PR, nightly | commit, PR | staging or test environment | CI (short), scheduled (long) |
| Output | CVE list with fix versions | file and line | URL and parameter | crashing input |

## 1. SCA (Software Composition Analysis)

SCA finds **known-vulnerable and risky third-party components**: it reads manifests, lock files, SBOMs, container layers or binaries, then matches components to advisory databases (OSV, GitHub Advisory Database, NVD, vendor feeds).

**Tools (verify what is current):** OSV-Scanner, Trivy, Grype, pip-audit, npm audit, OWASP Dependency-Check, Dependabot and Renovate (updates), and commercial platforms such as Snyk. **Syft/Trivy/cdxgen** make the SBOM; **Grype/osv-scanner** match it.

**Do it well.**

- Scan **lock files and the final image**, not only top-level manifests (transitive dependencies matter: the [lab](labs/sca/README.md) flags a vulnerable transitive package).
- **Prioritize**, do not drown: use severity plus **EPSS** (likelihood of exploitation) and the **CISA KEV** list (known exploited), then **reachability** (is the vulnerable code path used?) and **VEX** statements. The [CVSS/EPSS/KEV prioritizer](../../cybersecurity-track/08-vulnerability-management/README.md) lesson in this repo covers this.
- Fix by **upgrade**, replace, or mitigate; record accepted risks with an **owner and expiry**.
- SCA also covers **malicious packages**: dedicated tools such as GuardDog (Datadog) or Socket-style services inspect behavior, which CVE matching alone does not.
- A match is "possibly affected", not proof of exploitability.

**Lab:** [sca](labs/sca/README.md): lock file plus advisory DB, transitive findings, ignore-with-reason, CI exit code.

## 2. SAST

**Static Application Security Testing** analyzes source (or bytecode) **without running it**. It can run on partial code, early, and points to the exact line.

**How it works.** From simple pattern rules (regex or AST patterns), to **taint analysis** (track data from a **source** such as a request parameter to a **sink** such as a SQL call, unless a **sanitizer** intervenes), to full **data-flow and call-graph** analysis (CodeQL-style queries).

**Tools (verify):** Semgrep (rules in YAML; the open-source engine and its fork Opengrep exist, licenses changed in 2024-2025), Bandit (Python), CodeQL (GitHub), SonarQube, language-specific linters with security rules, and secret scanners (gitleaks, TruffleHog) as a special kind of SAST.

**Strengths:** early, cheap, line-level, finds classes of bug (injection, hardcoded secrets, weak crypto, unsafe deserialization). **Weaknesses:** **false positives** (flags safe code) and **false negatives** (misses flows through frameworks, reflection, containers); needs tuning; does not see runtime configuration.

**Handling noise:** start with a small high-confidence ruleset; **baseline** existing findings and gate only on **new** ones; allow `# nosec`-style suppressions only with a reason and review; track metrics (fix rate, false-positive rate).

**Lab:** [sast](labs/sast/README.md): 12 rules plus taint tracking, a vulnerable and a fixed app. Also see [CAISP ai-code-weaknesses](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/) (AI-generated code issues) and [CMCPSE SAST for an MCP server](../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/sast-vulnerable-mcp-server/README.md). Real tools: [real-tools/semgrep-and-bandit.md](real-tools/semgrep-and-bandit.md).

## 3. DAST

**Dynamic Application Security Testing** attacks a **running** application from outside, like an attacker: it **crawls** to find pages and parameters, then **probes** them (XSS markers, SQL error and boolean tests, SSRF canaries, path traversal), and does **passive checks** (headers, cookies, TLS, version leaks).

**Tools (verify):** OWASP ZAP (open source; its core team moved under Checkmarx's sponsorship in 2024, verify), Burp Suite (commercial, plus a free community edition), Nuclei (template-based), plus API-focused scanners that use an OpenAPI file.

**Strengths:** finds issues in the real deployed configuration; language-independent; few false positives for confirmed issues. **Weaknesses:** needs a running, reachable test environment; limited coverage (what is linked or described); authentication and state need setup; can be slow, and can **damage data**: **scan staging with test data, never production without agreement**.

**Tuning story from the lab.** The first version of the boolean SQL-injection check flagged an echo page. Fixing it (removing the echoed payload before comparing) is typical DAST work: confirm findings, then reduce noise.

**Lab:** [dynamic-analysis](labs/dynamic-analysis/README.md): local vulnerable app, crawler and prober, then the fixed app. Related: [pentest mini-app](../../cybersecurity-track/09-pentesting-fundamentals/lab/mini_app.py), [pentest methodology and tools](../../cybersecurity-track/09-pentesting-fundamentals/03-web-app-testing-and-burp.md). Real tools: [real-tools/zap.md](real-tools/zap.md).

**IAST and RASP (brief).** IAST puts an agent inside the running app during tests and sees both request and code (accurate, but needs instrumentation). RASP protects the app at runtime. Both complement the four above.

## 4. Fuzz Testing

**Fuzzing** runs a program with huge numbers of generated or mutated inputs to trigger crashes, memory errors, assertion failures and hangs. Modern fuzzers are **coverage-guided**: they keep inputs that reach new code, so they explore deeply.

| Piece | Meaning |
|---|---|
| **Harness** | a small function that feeds bytes to the code under test |
| **Corpus** | seed inputs that make mutation start from valid shapes |
| **Sanitizers** | AddressSanitizer, UBSan and others make bugs visible as crashes |
| **Oracles** | for non-memory bugs: invariants, round-trip checks, differential testing |

**Tools (verify):** AFL++, libFuzzer, Honggfuzz, Go's built-in fuzzing, Atheris (Python), Jazzer (JVM), cargo-fuzz (Rust); property-based testing with Hypothesis; **API fuzzing** (Schemathesis, RESTler); **OSS-Fuzz** and ClusterFuzzLite for continuous fuzzing of open-source and CI. Fuzzing found real bugs in parsers, decoders and protocol code.

**Where it fits.** Parsers and decoders (images, archives, YAML, protocols), anything that handles untrusted bytes, and the **tools in your supply chain** (package installers, archive extraction). Run short fuzz jobs on PRs and long ones on a schedule; keep crashing inputs as regression tests.

**Related lab:** the [CMCPSE fuzz-mcp-tools lab](../../cmcpse-course/ch5-devsecops-for-mcp-security/labs/fuzz-mcp-tools/README.md) fuzzes tool inputs offline. (Chapter 2's exercise list has a "Dynamic Analysis" lab; fuzzing is covered conceptually here and by that related lab.)

## 5. Putting it in the workflow: pre-commit and CI

| Stage | What to run | Why there |
|---|---|---|
| **Developer machine (pre-commit)** | fast, offline checks: secret detection, linters, SAST on **changed files**, formatters | instant feedback; keep under a few seconds |
| **Pull request (CI)** | full SAST, SCA on lock files, secret scan, IaC and container scans, unit tests, short fuzz | blocks merging; cannot be skipped (`--no-verify` only skips local hooks) |
| **Build** | SBOM generation, image scan, sign artifacts, provenance | produces evidence |
| **Staging** | DAST, API fuzzing, integration security tests | needs a running app |
| **Scheduled** | long fuzz runs, full dependency re-scan (new CVEs appear after release), rule updates | vulnerability data changes daily |
| **Production** | runtime monitoring, vulnerability management, SBOM queries | new CVEs, drift |

**Pre-commit specifics.** Hooks are client-side convenience; CI must repeat them ([sca-sast-pre-commit lab](labs/sca-sast-pre-commit/README.md) models the bypass and the CI backstop). A pre-commit config is **code that runs on every developer machine**: review it, pin revs, allowlist repos ([exploiting-pre-commit-hooks](labs/exploiting-pre-commit-hooks/README.md)). Keep hooks fast; heavy or networked scanners belong in CI. Real guide: [real-tools/pre-commit.md](real-tools/pre-commit.md).

**Triage workflow.** Dedupe findings across tools (DefectDojo-style aggregation), assign owners, set SLAs by severity and exploitability, and track **mean time to remediate**. A scanner nobody triages is noise.

## Hands-on

1. Run [sca](labs/sca/README.md), [sast](labs/sast/README.md) and [dynamic-analysis](labs/dynamic-analysis/README.md) in that order; fill the comparison table above with what each found in this chapter's apps.
2. Run [sca-sast-pre-commit](labs/sca-sast-pre-commit/README.md) and explain the `--no-verify` line.
3. Pick one real tool from [real-tools](real-tools/README.md) and run it on a small project you own.

## Real-world scenarios

1. **SCA reports 400 findings.** Prioritize by KEV, EPSS, reachability and internet exposure; fix ten that matter; baseline and schedule the rest.
2. **SAST flags a safe query as SQL injection.** Confirm the value is validated and parameterized elsewhere; suppress that line with a reason, or improve the rule; never turn the rule off globally.
3. **DAST finds nothing but a pentest finds IDOR.** DAST cannot judge authorization logic. Add authorization tests and manual testing.

## Common mistakes

- Running every scanner at commit time and making developers wait.
- Treating "zero findings" as "secure".
- Scanning only top-level dependencies.
- Letting scan results age without owners.
- DAST on production with write-capable payloads.

## Interview preparation

<details><summary><b>Q1. SAST versus DAST versus SCA versus fuzzing in one line each?</b></summary>
SAST reads your source for insecure patterns. DAST attacks the running app from outside. SCA finds known-vulnerable third-party components. Fuzzing throws mutated inputs at code to find crashes and parser bugs.
</details>

<details><summary><b>Q2. How do you reduce SAST false positives?</b></summary>
Start with high-confidence rules, add taint and sanitizer definitions, baseline old findings and gate on new ones, suppress only with a reason and review, and measure false-positive rates per rule.
</details>

<details><summary><b>Q3. Why can't pre-commit hooks be your only control?</b></summary>
They run on the developer's machine and can be skipped (`--no-verify`) or not installed. CI must run the same checks and enforce them with branch protection. Also, hook config is code that needs review.
</details>

<details><summary><b>Q4. How do you prioritize SCA findings?</b></summary>
Combine CVSS with EPSS and CISA KEV, check reachability and exposure, use VEX where available, and fix by upgrading or mitigating, with owners and deadlines.
</details>

<details><summary><b>Q5. Where does fuzzing fit and what does it need?</b></summary>
It fits code that parses untrusted input. It needs a harness, a seed corpus and sanitizers. Run short jobs in CI and long ones on a schedule; keep crashing inputs as regression tests.
</details>

## Checklist (definition of done)

- [ ] I can state what each of the four techniques finds and misses.
- [ ] I ran the four labs and compared outputs.
- [ ] I can design a workflow that places each technique and explain why.

## References

- OSV: <https://osv.dev/> · OSV-Scanner: <https://google.github.io/osv-scanner/>
- Semgrep: <https://semgrep.dev/docs/> · Bandit: <https://bandit.readthedocs.io/> · CodeQL: <https://codeql.github.com/>
- OWASP ZAP: <https://www.zaproxy.org/docs/>
- OSS-Fuzz: <https://google.github.io/oss-fuzz/> · AFL++: <https://aflplus.plus/>
- pre-commit: <https://pre-commit.com/>
- OWASP Application Security Verification Standard and DevSecOps Guideline: <https://owasp.org/>
- FIRST EPSS: <https://www.first.org/epss/> · CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
