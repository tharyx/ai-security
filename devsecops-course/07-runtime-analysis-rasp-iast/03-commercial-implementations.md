# Lesson 03: Commercial implementations of IAST and RASP (generic, hedged)

> **Sources merged:** [CDE 5] "A commercial implementation of the IAST tool" (the lab line). This lesson explains the product category. The deployment walkthrough is in [commercial-iast-walkthrough.md](labs/commercial-iast-walkthrough.md).
> **Time:** about 1 hour.

> **Hedged.** Product names, features and licensing change often. The list below is **examples only**, taken from the repo brief: verify everything at each vendor's site. This is not an endorsement or a comparison.

## 1. Examples of commercial IAST (and RASP) products

| Product family | Notes (verify) |
|---|---|
| **Contrast Security** | IAST and RASP from one agent family ("Assess" and "Protect" modes); agents for several languages; a management server (SaaS or on-prem) |
| **Datadog Code Security (IAST)** | IAST as part of an observability platform; uses the same tracing libraries as APM |
| **Seeker by Black Duck** (formerly from Synopsys) | IAST focused on the verification of findings, with agents and a server |
| Others exist | Check analyst reports and your cloud and APM vendors; some SAST/DAST suites include an IAST module |
| **OpenRASP** (Baidu) | An older open-source RASP project; useful to study the idea; check whether it is still maintained before using it |

Open-source options are **limited**; most IAST in enterprises is commercial. ZAP and similar tools are DAST, not IAST.

## 2. What they have in common (the architecture)

```text
+------------------+     +-------------------+     +-------------------------+
| Application      |     | Agent (in-process)|     | Management server       |
| (test env)       | --> | sources, sinks,   | --> | rules, findings, users, |
| + functional     |     | taint, traces     |     | licences, dashboards    |
|   tests / DAST   |     +-------------------+     +-----------+-------------+
+------------------+                                           |
                                                   API / webhook to CI gate,
                                                   ticketing, SIEM
```

1. **Agent**: attached with a JVM option, an environment variable, an npm/pip package, or an init container.
2. **Server (console)**: receives events, deduplicates, ranks, shows the trace, stores policy. SaaS or self-hosted.
3. **Policy**: which vulnerability rules are enabled, severity mapping, which environments report.
4. **CI integration**: a plugin or API call at the end of the test stage that asks "any new Critical/High findings for this build?" and sets pass or fail.
5. **Reporting**: findings in the console, tickets in your tracker, optional export to a findings database.

## 3. What to evaluate

| Area | Question |
|---|---|
| Language coverage | Your languages, versions, frameworks, app servers |
| Overhead | Measured on your app under load |
| Accuracy | False positives and false negatives on a known-vulnerable test app |
| Deployment | Containers, Kubernetes, serverless, ARM |
| CI/CD | Gate API, build and commit tagging, branches |
| Data handling | What leaves your network; masking; residency |
| Triage | Trace quality, remediation advice, ticketing |
| Production mode | Is RASP included? Monitor and block modes? Bypass switch? |
| Cost and licensing | Per app, per server, per usage; contract terms |
| Support and roadmap | SLAs, agent release cadence |

Test with your **own** application and a **known-vulnerable benchmark** (for example OWASP-style demo apps) and compare findings against what SAST and DAST found.

## 4. What the lab teaches you about them

The [IAST lab](labs/iast-instrumentation/README.md) is a toy, but it contains the same ideas as a commercial agent: sources, sinks, taint propagation, a trace, a mode switch (report versus block) and a coverage dependency on tests. When you use a commercial product, look for each of those parts and ask what it supports.

## 5. Summary

- IAST/RASP are mostly commercial; examples include Contrast Security, Datadog Code Security and Seeker (verify).
- The pattern is agent + server + CI gate + ticketing.
- Evaluate on your stack, with measured overhead and a known-vulnerable test app.
- Read data-handling terms before enabling an agent that sends traces to a vendor.
