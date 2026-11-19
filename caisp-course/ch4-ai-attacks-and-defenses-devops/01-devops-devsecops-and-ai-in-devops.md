# 01. DevOps, DevSecOps, and AI in DevOps

> **Syllabus:** Introduction to AI in DevOps: "Definition and Principles of DevOps and DevSecOps", "The Role of AI in Enhancing DevOps Practices".
> **Time:** 1 hour. You know DevOps well. This lesson reuses that knowledge and adds the AI angle.

## Why this matters

Your pipelines now build and ship models, not only services. At the same time AI tools write code, review pull requests and triage alerts inside those pipelines. That gives attackers two new doors: the **AI artifacts** moving through the pipeline, and the **AI helpers** working inside it.

## Definition and principles of DevOps and DevSecOps

**DevOps** joins development and operations so software ships faster and more reliably, with shared ownership. **DevSecOps** adds security to every step instead of at the end ("shift left", and also "keep watching on the right").

| Principle | DevOps meaning | DevSecOps addition |
|---|---|---|
| Automation | CI/CD, infrastructure as code | Security checks as code: SAST, SCA, secret scan, policy as code |
| Collaboration | Dev and Ops share goals | Security is a shared job; champions in teams |
| Continuous integration and delivery | Small, frequent, tested releases | Every change passes security gates; fast feedback |
| Infrastructure as code | Repeatable environments | Scan IaC; no manual drift |
| Monitoring and feedback | Metrics, logs, alerts | Security telemetry, detection, incident response |
| Least privilege and zero trust | n/a | Short-lived credentials, scoped roles, no implicit trust between stages |
| Supply chain integrity | n/a | SBOM, provenance, signing, pinned dependencies |

For AI, add **MLOps** (the same ideas for the model life cycle: data versioning, experiment tracking, model registry, continuous training) and **LLMOps** (prompts, evals, guardrails and model routing as first-class artifacts). Their security twin is sometimes called MLSecOps. Treat the names loosely; the point is that models, data and prompts need the same discipline as code.

New artifacts to put under control:

| AI artifact | Treat it like | Control |
|---|---|---|
| Dataset | Source code + sensitive data | Versioning, hashes, provenance, access control |
| Model file | A binary from a vendor | Format check, scan, sign, pin |
| Prompt / system prompt | Configuration and code | Version control, review, tests |
| Eval set and red-team suite | Test suite | Run in CI, fail the build on regressions |
| Vector index | A database | Access control, backups, poisoning checks |

## The role of AI in enhancing DevOps practices

AI helps with real work. Know the uses and the risk each one adds.

| Use | Benefit | New risk |
|---|---|---|
| **Coding assistants** (completion, chat, agents) | Faster code and tests | Insecure code, leaked secrets, hallucinated packages, prompt injection through repo files |
| **Automated code review and PR summaries** | Faster review | Reviewer trusts a summary; the summary can be manipulated by text in the PR |
| **Test generation** | Better coverage | Tests that assert wrong behavior; false confidence |
| **Pipeline authoring and IaC generation** | Speed | Over-permissive roles, open security groups, unpinned actions |
| **Log and alert triage, anomaly detection** | Less noise | Missed attacks, adversarial evasion, data leaving to a SaaS |
| **Incident response help** | Faster diagnosis | Wrong or fabricated remediation steps |
| **ChatOps agents with tool access** | Self-service operations | Excessive agency; commands run from untrusted chat or ticket text |
| **Predictive scaling, release risk scoring** | Efficiency | Poisoned input data skews decisions |

### Risks of AI coding assistants (the common exam topic)

1. **Insecure suggestions.** Models learned from public code, which includes vulnerable code. A suggestion looks confident and often compiles. Treat it like code from an unknown contributor: test, scan, review.
2. **Hallucinated dependencies.** An assistant may suggest a package that does not exist. An attacker can register that name ("slopsquatting"). Check new dependencies against an approved index. See the [hallucination lab](../ch3-llm-top-10-vulnerabilities/labs/hallucination-lab/README.md).
3. **Secrets and private code leaving the company.** Pasting code into an external assistant can expose it (compare the Samsung case in [chapter 3 lesson 06](../ch3-llm-top-10-vulnerabilities/06-sensitive-information-disclosure.md)). Choose approved tools, check retention and training terms.
4. **Prompt injection through the repository.** An assistant reads files, issues, README text and tool output. A hostile comment or "rules" file can steer it. Researchers have shown that instruction files for coding assistants can carry hidden instructions. Treat repo content as untrusted input.
5. **Excessive agency.** Agentic assistants can run commands, edit many files, push and call tools. Give them a sandbox, scoped tokens and approvals for risky actions.
6. **Licensing and provenance.** Generated code can resemble licensed code. Follow your legal policy.
7. **Overreliance.** Reviewers skim AI code because it "looks right". Keep human review and tests on every change.
8. **Poisoned assistant or extension.** The assistant plug-in itself is software with access to your code. Vet it like any dependency.

Controls that work: an approved-tools policy; secrets scanning and pre-commit hooks; SAST and SCA in CI for all code regardless of who wrote it; branch protection and mandatory human review; agents in sandboxes with least-privilege tokens; logging of assistant actions. The [ai-code-weaknesses lab](labs/ai-code-weaknesses/README.md) is a small SAST for AI code.

## Hands-on

- Read the repo [06-ai-devsecops overview](../../06-ai-devsecops/README.md).
- Run the [ai-code-weaknesses lab](labs/ai-code-weaknesses/README.md) on the sample app as if an assistant had written it.

## Interview Q&A

<details><summary><b>Q1. What is DevSecOps and how does it change for AI projects?</b></summary>
It builds security into every stage of delivery with automation and shared ownership. For AI you add controls for new artifacts (datasets, models, prompts, evals, vector indexes), run model-specific checks (pickle scan, safety evals, injection tests) and secure the AI helpers inside the pipeline.
</details>

<details><summary><b>Q2. Name five risks of AI coding assistants.</b></summary>
Insecure suggestions, hallucinated packages, secrets and code leaving the company, prompt injection through repo content, excessive agency of agentic tools, licensing, overreliance, and poisoned extensions.
</details>

<details><summary><b>Q3. How do you let developers use an assistant safely?</b></summary>
Approve specific tools with suitable data terms, scan every change with SAST/SCA/secret scanning, require review and tests, restrict what agents can run (sandbox, scoped tokens, approvals) and log activity.
</details>

## References

- OWASP DevSecOps Guideline: https://owasp.org/www-project-devsecops-guideline/
- NIST SP 800-218 Secure Software Development Framework (SSDF); NIST SP 800-218A for generative AI (verify at source)
- Repo: [06-ai-devsecops](../../06-ai-devsecops/README.md)
