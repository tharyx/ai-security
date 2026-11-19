# Chapter 07: Runtime Analysis (RASP/IAST) in CI/CD

This chapter covers **[CDE 5] Runtime Analysis (RASP/IAST) in CI/CD pipeline**: what runtime analysis is, how RASP and IAST differ, the challenges (language support, overhead, coverage depends on tests), suitability in CI/CD, and how commercial tools are deployed. Two labs build a toy agent in pure Python: an **IAST agent** that reports source-to-sink traces during functional tests, and a **RASP protect mode** that blocks a tainted SQL injection and measures overhead.

> **Safety.** Labs are offline: in-memory sqlite, a stub "shell" that never runs commands, a virtual file system with FAKE content, no network. Commercial tools are described generically and hedged: no vendor account is needed.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Product names change: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CDE 5] What is Runtime Analysis Application Security Testing? | [Lesson 01 sections 1 and 2](01-what-is-runtime-analysis-iast-and-rasp.md#1-the-gap-between-sast-and-dast) | [iast-instrumentation](labs/iast-instrumentation/README.md) |
| [CDE 5] Differences between RASP and IAST. | [Lesson 01 sections 3 to 6](01-what-is-runtime-analysis-iast-and-rasp.md#3-iast-interactive-application-security-testing) (SVG) | [iast-instrumentation](labs/iast-instrumentation/README.md), [rasp-blocking](labs/rasp-blocking/README.md) |
| [CDE 5] Runtime Analysis and challenges. | [Lesson 02 section 1](02-challenges-and-cicd-suitability.md#1-the-challenges) | [iast-instrumentation](labs/iast-instrumentation/README.md) (coverage, false negatives), [rasp-blocking](labs/rasp-blocking/README.md) (overhead) |
| [CDE 5] RASP/IAST and its suitability in CI/CD pipeline. | [Lesson 02 sections 2 to 4](02-challenges-and-cicd-suitability.md#2-suitability-in-cicd) | [iast-instrumentation](labs/iast-instrumentation/README.md), [commercial-iast-walkthrough](labs/commercial-iast-walkthrough.md) (CI gate) |
| [CDE 5] Hands-On Labs: | Header line: the lab below | [commercial-iast-walkthrough](labs/commercial-iast-walkthrough.md) |
| [CDE 5] A commercial implementation of the IAST tool. | [Lesson 03](03-commercial-implementations.md) (generic, hedged); [commercial IAST walkthrough](labs/commercial-iast-walkthrough.md) (Contrast-style) | [iast-instrumentation](labs/iast-instrumentation/README.md) and [rasp-blocking](labs/rasp-blocking/README.md) are the offline twins |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| "Runtime Analysis Application Security Testing" | Not a standard industry term. The usual names are **IAST** (test time) and **RASP** (production). |
| "A commercial implementation of the IAST tool" (unnamed) | Examples of commercial products: Contrast Security, Datadog Code Security (IAST), Seeker by Black Duck. Product lines are renamed and acquired often. Check each vendor. |
| Open-source RASP | Few options. **OpenRASP** (Baidu) is older: check maintenance before use. Most IAST/RASP is commercial. |
| IAST/RASP as one family | Some vendors ship one agent with two modes (assess and protect). Others sell separate products. |
| Language support | Strongest for Java and .NET; Node, Python, Ruby and others vary; Go and Rust are harder. Verify for your stack and framework versions. |

## How the three courses overlap here

Only the Expert course has a runtime analysis chapter (CDE 5). The Professional course (CDP) covers SAST, SCA and DAST only; the Container course covers **runtime security of containers** (Falco, Tracee, AuditD) in [chapter 12](../12-container-security-monitoring/README.md), which is a different layer: those tools watch **system calls and containers**, while IAST/RASP watch **application code and data flow**. Use both. This chapter builds on [chapter 05 (static analysis)](../05-static-analysis-and-secrets/README.md) and [chapter 06 (dynamic analysis)](../06-dynamic-analysis/README.md): IAST is most useful when a DAST scan or QA suite drives traffic through the instrumented app. Also see the [secure AI gateway lesson](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md) for a runtime enforcement point at a different layer.

## Learning order

1. [Lesson 01](01-what-is-runtime-analysis-iast-and-rasp.md) (SVG), then [iast-instrumentation](labs/iast-instrumentation/README.md). About 4 hours.
2. [rasp-blocking](labs/rasp-blocking/README.md). About 2 hours.
3. [Lesson 02](02-challenges-and-cicd-suitability.md). About 2 hours.
4. [Lesson 03](03-commercial-implementations.md) and the [commercial IAST walkthrough](labs/commercial-iast-walkthrough.md). About 2 hours.
5. Then [Chapter 08](../08-iac-configuration-and-compliance-as-code/README.md).

## Lab index

Run all: `.venv/Scripts/python -m pytest devsecops-course/07-runtime-analysis-rasp-iast`.

| Lab | Exercise | Tests |
|---|---|---|
| [iast-instrumentation](labs/iast-instrumentation/README.md) | pure-Python IAST agent: taint tracking, source to sink traces from functional tests | 10 |
| [rasp-blocking](labs/rasp-blocking/README.md) | the same agent in protect mode; blocks SQLi, path traversal, command injection; overhead benchmark | 8 |
| [commercial-iast-walkthrough](labs/commercial-iast-walkthrough.md) | hedged guide: agent, server and CI gate of a commercial IAST | guide |

## Exam tips

- **IAST finds, RASP blocks.** IAST runs in test and reports with a code trace; RASP runs in production and stops attacks.
- **Both are in-process agents** that use instrumentation and taint tracking: sources, propagators, sinks, sanitizers.
- **IAST needs traffic**: functional tests, API tests or a DAST scan. Coverage depends on tests: "found nothing" means "nothing on the tested paths".
- **IAST does not need attack payloads**; it flags unsafe construction. RASP needs to judge whether the payload is hostile.
- **Challenges list:** language and framework support, overhead, test coverage, lost taint, false blocks, agent risk and data sharing, cost.
- **Roll out RASP in monitor mode first**, then block, with a bypass switch.
- **WAF versus RASP:** a WAF sees HTTP text from outside; RASP sees the value at the sink inside the app.
- **CI fit:** IAST rides the test stage and gates on new High findings; RASP is a runtime control, not a pipeline test.
- **Name vendors only as examples** and hedge them.

## 15 exam-style questions

<details>
<summary>1. What is runtime analysis in application security?</summary>

Putting an agent inside the running application that watches code execution, tracks untrusted data from sources to sinks, and either reports vulnerabilities (IAST) or blocks attacks (RASP).
</details>

<details>
<summary>2. How does IAST differ from RASP?</summary>

IAST runs in test environments, is driven by tests or DAST, and reports flaws with a source-to-sink trace. RASP runs in production, is driven by real traffic, and blocks hostile requests at the sink and raises alerts.
</details>

<details>
<summary>3. How does an agent get inside the application?</summary>

Through instrumentation: a Java agent or .NET profiler that rewrites bytecode, or a library that wraps sensitive functions in Node, Python or Ruby. It runs in the same process.
</details>

<details>
<summary>4. Explain taint tracking.</summary>

Data from a source (HTTP parameter) is marked tainted, the mark follows the data through concatenation and copying, and an alert is raised when tainted data reaches a sink (SQL execute, OS command, file open) without a sanitizer.
</details>

<details>
<summary>5. Why can IAST report SQL injection even with harmless test data?</summary>

It looks at how the SQL string was built. If untrusted data is concatenated into the statement instead of bound as a parameter, the flow is vulnerable regardless of the value used in the test.
</details>

<details>
<summary>6. What does "coverage depends on tests" mean for IAST?</summary>

The agent only sees code that executes. A path never exercised by a test or scan produces no finding, so a clean IAST report only covers the exercised paths. Improve coverage with more tests and DAST traffic.
</details>

<details>
<summary>7. Give three challenges of runtime analysis.</summary>

Language and framework support; performance overhead (CPU, memory, latency); coverage limited by tests; lost taint through unsupported operations; false blocks in RASP; operating an agent and sharing data with a vendor; cost.
</details>

<details>
<summary>8. Why is overhead a bigger concern for RASP than IAST?</summary>

RASP runs in production on every user request, so latency and resource use affect customers. IAST runs only in test environments. Measure p50 and p99 latency with and without the agent under realistic load.
</details>

<details>
<summary>9. How should you roll out RASP safely?</summary>

Start in monitor mode, send alerts to the SIEM, review false positives for a period, tune and allowlist, then enforce on high-confidence classes such as SQL injection first, and keep a bypass switch that does not need a redeploy.
</details>

<details>
<summary>10. How does IAST fit in a CI/CD pipeline?</summary>

Deploy a build with the agent to a test environment, run functional, API and DAST tests, query the IAST server for new findings of this build, gate on new High findings (and on "agent not connected"), and send results to the findings tracker.
</details>

<details>
<summary>11. Why is RASP not a replacement for fixing the code?</summary>

It is a compensating control: a virtual patch that buys time. It can have gaps and false blocks, and it adds overhead. The root fix is in the code (parameterised queries, validation).
</details>

<details>
<summary>12. Compare RASP and a WAF.</summary>

A WAF sits in front of the app and sees HTTP text, so it can be bypassed with encodings and lacks context. RASP sits inside the app and sees the value at the sink after decoding, so it has better context and fewer false positives, at the cost of agent overhead and language support.
</details>

<details>
<summary>13. Name some commercial IAST products and how to treat the list.</summary>

Examples: Contrast Security, Datadog Code Security (IAST), Seeker by Black Duck. Present them as examples only, hedge them, and say to verify features and licensing with the vendor. Evaluate on your own stack.
</details>

<details>
<summary>14. What components does a commercial IAST deployment have?</summary>

An agent attached to the application, a management server (SaaS or self-hosted) holding policy and findings, a CI integration or API to gate builds, and integrations for tickets and SIEM.
</details>

<details>
<summary>15. When is IAST a poor fit?</summary>

When there is no functional test suite, when the language or framework is unsupported, when an in-process agent is not allowed, or when the latency budget cannot accept any overhead. DAST, SAST and runtime protection tools at other layers may fit better.
</details>

## References

- OWASP resources on IAST and RASP; OWASP Top 10 (injection); OWASP Application Security Verification Standard (ASVS).
- NIST guidance on secure software development (SSDF, SP 800-218) for testing activities.
- Vendor documentation (Contrast Security, Datadog Code Security, Black Duck Seeker): verify current names and features.
- OpenRASP project (Baidu): study the idea; check maintenance.
- Repo: [chapter 05](../05-static-analysis-and-secrets/README.md), [chapter 06](../06-dynamic-analysis/README.md), [chapter 12](../12-container-security-monitoring/README.md), [secure AI gateway](../../09-enterprise-architecture/06-secure-llm-ai-gateway.md), [csse ch2 dynamic-analysis lab](../../csse-course/ch2-attacking-code-and-application-supply-chain/labs/dynamic-analysis/README.md).
