# 02. Types of AI Attacks on DevOps Teams

> **Syllabus:** Introduction to AI in DevOps: "Types of AI Attacks on DevOps Teams".
> **Time:** 1 hour. Two directions: attackers **using AI** against your team, and attackers **attacking the AI** your team uses or ships.

## Why this matters

DevOps teams hold the keys: cloud accounts, registries, signing keys, production access. That makes them a favorite target. AI makes some attacks cheaper (better phishing) and adds new targets (models, prompts, agents, datasets).

## Understand it

### Direction A: AI used as a weapon against the team

| Attack | What it is | Defender view |
|---|---|---|
| **AI-written phishing and BEC** | Fluent, personalized messages with no typos, in any language, produced at scale | Do not rely on "bad grammar" as a signal. Use phishing-resistant MFA (passkeys, security keys), mail authentication (SPF, DKIM, DMARC), out-of-band verification for payment and access requests |
| **Voice and video deepfakes** | A fake call or video "from the CTO" asking for urgent access or a pipeline change | Call-back procedures, a second approver, no approvals by voice or video alone |
| **Faster reconnaissance** | Automating the reading of public repos, job posts and leaked data to find targets | Reduce what is public; scan your repos and history for secrets |
| **Criminal LLM services** | In 2023, services such as "WormGPT" and "FraudGPT" were reported on forums. Many were scams or wrappers around public models, sold for phishing and similar tasks | Threat-intelligence view only: defend the same way as for any phishing or fraud, and watch the forums through your threat-intel provider. Do not use or seek them |
| **Assisted exploit or malware development** | AI lowers the skill needed for routine tasks | Patch fast, detect behavior not signatures, keep EDR and logging |
| **Credential and token theft at speed** | Automated search for leaked keys in code and logs | Secret scanning, short-lived tokens, rotate on exposure |

### Direction B: attacks on the AI that DevOps teams build or use

| Attack | Target in the pipeline | Example (simulated in this course) |
|---|---|---|
| **Prompt injection of DevOps agents** | An AI that reads issues, PR text, alerts, tickets or logs and then acts | A hidden instruction in an issue makes a triage bot post a secret or merge a change. See [llm-agent-vuln-scan](labs/llm-agent-vuln-scan/README.md) |
| **Poisoned coding assistant input** | Rules files, README text, docs, comments | Hidden text steers generated code (insecure defaults, a malicious dependency) |
| **Hallucinated dependency (slopsquatting)** | Package install commands copied from an assistant | An attacker registers the made-up name. See the [hallucination lab](../ch3-llm-top-10-vulnerabilities/labs/hallucination-lab/README.md) |
| **Malicious or trojaned models** | Model downloaded from a hub | Pickle code execution on load. See [picklescan lab](labs/picklescan/README.md) |
| **Training data poisoning** | Data stores and ingestion jobs | Backdoor planted before training ([chapter 3 lesson 03](../ch3-llm-top-10-vulnerabilities/03-training-data-poisoning.md)) |
| **Poisoned pipeline execution** | CI/CD definitions and the files they run | A pull request makes the runner execute attacker code. See [lesson 04](04-pipeline-attacks-and-ppe.md) |
| **Compromised AI platform or tenant** | Managed AI services, shared clusters | Cross-tenant access (SAP AI Core case, [lesson 05](05-case-studies.md)) |
| **Model and data theft from the pipeline** | Registries, artifact stores, runners with cloud roles | Stolen tokens read the weights |
| **Abuse of MCP servers and tools** | Tools connected to agents | Poisoned tool descriptions, over-broad tools ([chapter 3 lesson 07](../ch3-llm-top-10-vulnerabilities/07-insecure-plugin-design.md)) |
| **Evasion of AI-based defenses** | Anomaly detectors, AI code scanners | Inputs crafted so the detector stays quiet |
| **Resource abuse** | GPU clusters, paid APIs | Cryptomining or "denial of wallet" with stolen keys |

### How the two directions meet

A typical chain: an AI-written phishing email steals a developer's token (A) → the token opens a PR that poisons the pipeline (B) → the pipeline publishes a trojaned model. Defend each link, because you will not stop all of them.

## Defend it

| Layer | Control |
|---|---|
| People | Phishing-resistant MFA, verification rules for requests, deepfake awareness, a safe way to report |
| Identity | Short-lived, scoped tokens; separate roles for build and deploy; no long-lived keys in CI |
| Pipeline | Protected pipeline files, no secrets for untrusted code, approvals ([lesson 04](04-pipeline-attacks-and-ppe.md)) |
| Artifacts | Sign and verify models and images; scan them; pin versions |
| AI helpers | Sandboxes, least privilege, approvals; treat repo and ticket text as untrusted |
| Detection | Audit logs for registry and pipeline events; alerts on unusual token use |
| Testing | Red-team the pipeline and the agents; run the probes in CI |

## Hands-on

Run [llm-agent-vuln-scan](labs/llm-agent-vuln-scan/README.md) and [poisoned-pipeline](labs/poisoned-pipeline/README.md).

## Interview Q&A

<details><summary><b>Q1. Give two ways attackers use AI against DevOps teams and two ways they attack the AI itself.</b></summary>
Using AI: convincing phishing and deepfake voice/video requests. Attacking AI: prompt injection of agents that read tickets and PRs, and trojaned model files or poisoned data and pipelines.
</details>

<details><summary><b>Q2. How would you protect a pipeline from a deepfake call that says "approve this release now"?</b></summary>
Never approve by voice or video alone. Use a second approver in the tool, a call-back to a known number, and a change process that does not allow bypass for urgency.
</details>

<details><summary><b>Q3. What are criminal LLM services like WormGPT, and how should defenders treat them?</b></summary>
Reported in 2023 as services sold on forums for phishing and similar tasks; many were scams or wrappers on public models. Treat them as part of the phishing and fraud threat: strong email and MFA controls, verification procedures and threat intelligence. Do not use them.
</details>

## References

- MITRE ATLAS (tactics and techniques for AI systems): https://atlas.mitre.org/ (check current tactic names)
- OWASP Top 10 CI/CD Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- Repo: [06 cicd](../../06-ai-devsecops/cicd/README.md), [05-agent-security](../../05-agent-security/README.md)
