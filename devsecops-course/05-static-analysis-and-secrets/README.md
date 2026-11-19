# Chapter 05: Static Analysis (SAST) and Secrets in the CI/CD Pipeline

This chapter covers **finding vulnerabilities and leaked secrets in source code before it runs**: what SAST is and where it struggles, how to embed SpotBugs (successor of FindBugs), Brakeman and Bandit, how secret scanning works (including the history of a git repository), why a pre-commit hook is not your gate, and how to **write custom rules** with regular expressions, ASTs and data and control flow (taint) analysis. Five labs run offline with fixtures and tests; **Java, Ruby, Bandit, TruffleHog and the network are not required**.

> **Safety.** All scanned code is fixture code that is only parsed. Every secret is FAKE and **built at runtime from pieces**, so no source file contains a token-shaped literal. The git lab uses a temporary repository and isolated git config. Scan only code you own.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CDP 5] SAST (Static Analysis) in CI/CD pipeline | [Lesson 01](01-sast-basics-and-tools.md), [Lesson 02](02-secrets-scanning-and-pre-commit.md) | all five labs |
| [CDP 5] What is Static Application Security Testing. | [01 section 1](01-sast-basics-and-tools.md#1-what-is-sast); repo [CSE ch2 SAST lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sast/README.md), [CMCPSE ch5 SAST and secrets](../../cmcpse-course/ch5-devsecops-for-mcp-security/02-sast-and-secret-scanning.md) | [brakeman-bandit](labs/brakeman-bandit/README.md) |
| [CDP 5] Static Analysis and Its challenges. | [01 section 2](01-sast-basics-and-tools.md#2-challenges-of-static-analysis); repo [CSE ch6 false-positive-analysis](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/false-positive-analysis/README.md), [CAISP ai-code-weaknesses](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/README.md) | [spotbugs-java-scan](labs/spotbugs-java-scan/README.md) (triage), [bandit-custom-checks](labs/bandit-custom-checks/README.md) (false positives) |
| [CDP 5] Embedding SAST tools like Find Bugs into the pipeline. | [01 sections 3 and 4](01-sast-basics-and-tools.md#3-tools-by-language) (FindBugs is dead, SpotBugs + find-sec-bugs; Brakeman, Bandit, Semgrep, CodeQL) (SVG); [real-tools/sast-tools.md](real-tools/sast-tools.md); repo [CSE ch6 sast-in-pipeline](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/sast-in-pipeline/README.md) | [spotbugs-java-scan](labs/spotbugs-java-scan/README.md) |
| [CDP 5] Secrets scanning to prevent secret exposure in the code. | [Lesson 02 sections 1 and 2](02-secrets-scanning-and-pre-commit.md#2-how-secret-scanners-work) (SVG); [real-tools/secrets-tools.md](real-tools/secrets-tools.md); repo [CSE ch6 trufflehog](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trufflehog-secrets-scan/README.md), [trivy-secrets-scan](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/trivy-secrets-scan/README.md), [CMCPSE ch5 secret scanner](../../cmcpse-course/ch5-devsecops-for-mcp-security/02-sast-and-secret-scanning.md) | [trufflehog-gitrob-secrets](labs/trufflehog-gitrob-secrets/README.md) |
| [CDP 5] Writing custom checks to catch secrets leakage in an organization. | [02 section 3](02-secrets-scanning-and-pre-commit.md#3-writing-custom-checks-for-secret-leakage-in-your-organisation) | [trufflehog-gitrob-secrets](labs/trufflehog-gitrob-secrets/README.md) (internal token format with checksum) |
| [CDP 5] Hands-On Labs: | Labs below | [Lab index](#lab-index) |
| [CDP 5] using SpotBugs to scan Java code. | [01 section 3](01-sast-basics-and-tools.md#3-tools-by-language); [real-tools/sast-tools.md](real-tools/sast-tools.md) | [spotbugs-java-scan](labs/spotbugs-java-scan/README.md) |
| [CDP 5] using trufflehog/gitrob to scan for secrets in CI/CD pipeline. | [Lesson 02](02-secrets-scanning-and-pre-commit.md) (gitrob is unmaintained; TruffleHog, gitleaks, detect-secrets are current); [real-tools/secrets-tools.md](real-tools/secrets-tools.md) | [trufflehog-gitrob-secrets](labs/trufflehog-gitrob-secrets/README.md) |
| [CDP 5] using brakeman/bandit to scan Ruby on Rails and Python Code Base. | [01 section 3](01-sast-basics-and-tools.md#3-tools-by-language); [real-tools/sast-tools.md](real-tools/sast-tools.md) | [brakeman-bandit](labs/brakeman-bandit/README.md) |
| [CDE 3] Advanced Static Analysis (SAST) in CI/CD pipeline | [Lesson 02](02-secrets-scanning-and-pre-commit.md), [Lesson 03](03-custom-rules-regex-ast-graph.md) | [bandit-custom-checks](labs/bandit-custom-checks/README.md), [custom-rules-regex-ast-graph](labs/custom-rules-regex-ast-graph/README.md) |
| [CDE 3] Why pre-commit hooks are not a good fit in DevSecOps. | [02 section 5](02-secrets-scanning-and-pre-commit.md#5-why-pre-commit-hooks-are-not-a-good-fit-in-devsecops) (SVG); contrast with repo [CSE ch2 pre-commit-hooks](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/pre-commit-hooks/README.md), [sca-sast-pre-commit](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/sca-sast-pre-commit/README.md), [exploiting-pre-commit-hooks](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/exploiting-pre-commit-hooks/README.md) | [trufflehog-gitrob-secrets](labs/trufflehog-gitrob-secrets/README.md) (CI range scan) |
| [CDE 3] Writing custom rules to weed out false positives and improve the quality of the results. | [03 section 1](03-custom-rules-regex-ast-graph.md#1-why-write-custom-rules-at-all) | [bandit-custom-checks](labs/bandit-custom-checks/README.md) (5 false positives down to 0) |
| [CDE 3] Various approaches to write custom rules in free and paid tools | [03 sections 2 to 4](03-custom-rules-regex-ast-graph.md#2-three-approaches) (SVG); [real-tools/semgrep-codeql.md](real-tools/semgrep-codeql.md) | [custom-rules-regex-ast-graph](labs/custom-rules-regex-ast-graph/README.md) |
| [CDE 3] Regular expressions | [03 section 2.1](03-custom-rules-regex-ast-graph.md#21-regular-expressions) | [custom-rules-regex-ast-graph](labs/custom-rules-regex-ast-graph/README.md), [trufflehog-gitrob-secrets](labs/trufflehog-gitrob-secrets/README.md) |
| [CDE 3] Abstract Syntax Trees | [03 section 2.2](03-custom-rules-regex-ast-graph.md#22-abstract-syntax-trees) | [custom-rules-regex-ast-graph](labs/custom-rules-regex-ast-graph/README.md), [bandit-custom-checks](labs/bandit-custom-checks/README.md) |
| [CDE 3] Graphs ( Data and Control Flow analysis) | [03 section 2.3](03-custom-rules-regex-ast-graph.md#23-graphs-data-and-control-flow) (a tiny taint tracker, source to sink without sanitizer); CodeQL and Semgrep taint mode in [real-tools/semgrep-codeql.md](real-tools/semgrep-codeql.md) | [custom-rules-regex-ast-graph](labs/custom-rules-regex-ast-graph/README.md) |
| [CDE 3] Hands-on Labs: | Labs below | [Lab index](#lab-index) |
| [CDE 3] Writing custom checks in the bandit for your enterprise applications. | [03 section 5](03-custom-rules-regex-ast-graph.md#5-the-bandit-style-lab); real Bandit plugin skeleton in [real-tools/sast-tools.md](real-tools/sast-tools.md#real-bandit-plugin-skeleton-custom-check) | [bandit-custom-checks](labs/bandit-custom-checks/README.md) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| **Find Bugs** | **FindBugs** stopped around 2015. Use **SpotBugs** (the successor) and add **find-sec-bugs** for security rules and CWE ids. The lab is already titled SpotBugs. |
| **gitrob** | **Unmaintained.** Use **TruffleHog** (verification), **gitleaks** or **detect-secrets**; consider GitHub secret scanning and push protection. The file-name-signature idea is kept in the lab. |
| **trufflehog** | Current TruffleHog is v3 (Go, many detectors, optional live verification). Older Python versions of the course are different tools with the same name. |
| **Brakeman, Bandit** | Both current. Brakeman has no severity (only confidence); Bandit has a plugin API (entry point `bandit.plugins`) for custom checks. |
| **Custom rules "in free and paid tools"** | Free: **Semgrep** (open-source engine; the **Opengrep** fork exists since 2025) and **CodeQL** (free for open source, licensed for private code; verify). Paid: SonarQube editions, Checkmarx, Fortify, Snyk Code, Semgrep platform. |
| **Pre-commit hooks** | Still useful as developer feedback, but **never the gate**: client side, skippable (`--no-verify`), slow and inconsistent. Enforce in CI with protected branches. |
| **SAST for "your" code only** | Also scan AI-generated code and infrastructure code; see [CAISP ai-code-weaknesses](../../caisp-course/ch4-ai-attacks-and-defenses-devops/labs/ai-code-weaknesses/README.md). |

## Learning order

1. [Lesson 01](01-sast-basics-and-tools.md): SAST, challenges, tools. About 2 hours.
2. [spotbugs-java-scan](labs/spotbugs-java-scan/README.md), then [brakeman-bandit](labs/brakeman-bandit/README.md). About 2 hours.
3. [Lesson 02](02-secrets-scanning-and-pre-commit.md), then [trufflehog-gitrob-secrets](labs/trufflehog-gitrob-secrets/README.md) and the [secrets tools guide](real-tools/secrets-tools.md). About 3 hours.
4. [Lesson 03](03-custom-rules-regex-ast-graph.md), then [bandit-custom-checks](labs/bandit-custom-checks/README.md) and [custom-rules-regex-ast-graph](labs/custom-rules-regex-ast-graph/README.md). About 5 hours.
5. [Real-tool notes](real-tools/sast-tools.md) and [Semgrep and CodeQL](real-tools/semgrep-codeql.md). About 1 hour.
6. Then [Chapter 06: Dynamic Analysis](../06-dynamic-analysis/README.md).

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest devsecops-course/05-static-analysis-and-secrets`.

| Lab | Course exercise | Tests |
|---|---|---|
| [bandit-custom-checks](labs/bandit-custom-checks/README.md) | Writing custom checks in the bandit for your enterprise applications | 12 |
| [spotbugs-java-scan](labs/spotbugs-java-scan/README.md) | using SpotBugs to scan Java code | 8 |
| [trufflehog-gitrob-secrets](labs/trufflehog-gitrob-secrets/README.md) | using trufflehog/gitrob to scan for secrets in CI/CD pipeline | 13 (3 need git) |
| [brakeman-bandit](labs/brakeman-bandit/README.md) | using brakeman/bandit to scan Ruby on Rails and Python Code Base | 9 |
| [custom-rules-regex-ast-graph](labs/custom-rules-regex-ast-graph/README.md) | Regular expressions, Abstract Syntax Trees, Graphs | 12 |

Hedged guides for real tools: [SAST tools](real-tools/sast-tools.md), [secrets tools](real-tools/secrets-tools.md), [Semgrep and CodeQL](real-tools/semgrep-codeql.md).

## How the three courses overlap here

- **CDP 5** (the basics: what SAST is, tools, secrets, three tool labs) and **CDE 3** (advanced: why not pre-commit, custom rules, regex, AST, graphs, Bandit plugin) are merged into one sequence: tools first, then customisation. Nothing is taught twice; false-positive reduction appears once, in lesson 03, and the labs reference it.
- **CCSE** teaches SAST and pre-commit inside its code supply chain chapter ([CSE ch2](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md): SAST, SCA/SAST pre-commit hooks, attacks on hooks) and TruffleHog, Trivy secrets, false-positive analysis and SAST in pipelines in [CSE ch6](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/README.md). Those labs show how to **set hooks up and attack them**; this chapter explains why the **gate belongs in CI**, and adds named SAST tools and custom rules. They are linked, not repeated.
- **CMCPSE and CAISP** have SAST and secrets labs for MCP servers and AI-written code; the techniques are the same.
- SCA is [chapter 04](../04-software-component-analysis/README.md); DAST is [chapter 06](../06-dynamic-analysis/README.md); secrets management (vaults) is [chapter 13](../13-secrets-management/README.md).

## Exam tips

- **SAST analyses code without running it;** name the strengths (early, exact line, CWE) and weaknesses (false positives, no runtime context, language coverage).
- **FindBugs to SpotBugs, plus find-sec-bugs.** Bytecode analysis, so build first.
- **Brakeman is Rails-only and reports confidence, not severity;** Bandit is Python AST with plugins.
- **A deleted secret is still in history.** Rotate first; scan history and all branches; scan the CI range.
- **Detection techniques:** provider regex, generic assignment, entropy, file-name signatures, verification, checksums.
- **gitrob is unmaintained;** name TruffleHog, gitleaks and detect-secrets.
- **Pre-commit is feedback, CI is the gate.** Give three reasons.
- **Three rule approaches:** regex (text), AST (structure), graph or taint (data flow); give a strength and weakness of each.
- **Taint terms:** source, propagation, sanitizer, sink.
- **Measure rules:** precision and recall against labelled examples; test every rule with positive and negative cases.
- **Gate on new findings,** with expiring suppressions.

## 15 exam-style questions

<details>
<summary>1. What is SAST and what are its main limits?</summary>

Static Application Security Testing analyses source or bytecode without running it. It is early and points to exact lines. Limits: false positives and negatives, no runtime context, coverage depends on language and framework, tuning effort.
</details>

<details>
<summary>2. How do you reduce false positives from a SAST tool?</summary>

Tune or disable noisy rules with justification, write custom rules that know your frameworks and safe helpers, gate on new findings only, keep triage decisions with reasons and expiry, and measure precision on labelled examples.
</details>

<details>
<summary>3. What is the relation between FindBugs, SpotBugs and find-sec-bugs?</summary>

FindBugs is the old, unmaintained bytecode bug finder. SpotBugs is its maintained successor. find-sec-bugs is a plugin with security patterns and CWE references for SpotBugs.
</details>

<details>
<summary>4. Why are SpotBugs ranks useful in a gate?</summary>

Rank 1 to 20 combines severity and confidence (1-4 scariest, 5-9 scary, 10-14 troubling, 15-20 of concern). A gate on rank is easy to explain and tune. Combine it with category and path filters.
</details>

<details>
<summary>5. How does Brakeman report risk, and how do you build a severity policy for it?</summary>

It reports a warning type and a confidence (High, Medium, Weak) but no severity. Teams map warning types or CWEs to a severity (for example SQL injection high, open redirect low) and combine it with confidence into a score.
</details>

<details>
<summary>6. What is a Bandit plugin, in short?</summary>

A Python function registered for AST node types (for example `Call`) with a test id; it receives a context (callee name, arguments, keywords) and returns an Issue with severity, confidence and CWE. Plugins are discovered through the `bandit.plugins` entry point. `# nosec` suppresses a line.
</details>

<details>
<summary>7. Why does deleting a secret from the code not fix a leak?</summary>

Git keeps history on every clone and branch. The secret remains in earlier commits, forks and CI caches. You must revoke and rotate it, then scan history and prevent recurrence.
</details>

<details>
<summary>8. Name four ways secret scanners detect secrets and one weakness of each.</summary>

Provider regex (only known formats); generic assignment (placeholders and test data); entropy (hashes and UUIDs look random); file-name signatures (name only); verification (needs network and sends the secret to the provider); checksums (only formats with a check digit).
</details>

<details>
<summary>9. What is the status of gitrob and what replaces it?</summary>

gitrob is unmaintained (verify). Use TruffleHog (with verification), gitleaks or detect-secrets, plus platform features such as GitHub secret scanning and push protection.
</details>

<details>
<summary>10. Why are pre-commit hooks not a good fit as a security control?</summary>

They run client-side and can be skipped (`--no-verify`) or never installed; slow hooks get disabled; versions drift; there is no central evidence; they see only staged changes, not history; hook configuration is itself an attack surface. Use them as feedback and enforce the same checks in CI with protected branches.
</details>

<details>
<summary>11. Compare regex, AST and graph rules.</summary>

Regex matches text: fast, any language, blind to structure and variables. AST rules match code structure: understand calls and arguments, fold constants, but not data origin. Graph rules follow data and control flow: they find source-to-sink paths and respect sanitizers, but need modelled sources, sinks and sanitizers and more effort.
</details>

<details>
<summary>12. Define source, sink and sanitizer in taint analysis.</summary>

A source is where untrusted data enters (request parameters). A sink is a dangerous operation (SQL execute, shell, eval). A sanitizer makes data safe for a sink (a cast to int, escaping, parameterised queries). A finding is a path from source to sink that avoids sanitizers.
</details>

<details>
<summary>13. Why did the AST detector in the lab miss the query built in a variable?</summary>

It only inspects the call's first argument. A variable is just a `Name`, and the AST alone does not know how it was built. A data-flow detector follows the variable back to its assignment.
</details>

<details>
<summary>14. Which free and paid tools let you write custom rules?</summary>

Free: Bandit plugins, Semgrep (open-source engine, Opengrep fork), CodeQL for open-source code, ESLint rules. Paid or mixed: Semgrep platform, SonarQube editions, Checkmarx, Fortify, Snyk Code. Verify current licensing.
</details>

<details>
<summary>15. How do you prove that a custom rule is good?</summary>

Test it against labelled examples: lines that must be flagged and lines that must not. Measure precision (share of findings that are real) and recall (share of real bugs found), version the rule, and re-measure when code or the rule changes.
</details>

## References

- SpotBugs, find-sec-bugs, Brakeman, Bandit, Semgrep, CodeQL, TruffleHog, gitleaks, detect-secrets and pre-commit documentation (verify current versions); SARIF 2.1.0 (OASIS).
- MITRE CWE; OWASP Source Code Analysis Tools; OWASP Secrets Management Cheat Sheet.
- Repo: [CSE ch2](../../csse-course/ch2-attacking-code-and-application-supply-chain/README.md), [CSE ch6](../../csse-course/ch6-common-defenses-against-supply-chain-attacks/README.md), [CMCPSE ch5](../../cmcpse-course/ch5-devsecops-for-mcp-security/README.md), [CAISP ch4](../../caisp-course/ch4-ai-attacks-and-defenses-devops/README.md).
