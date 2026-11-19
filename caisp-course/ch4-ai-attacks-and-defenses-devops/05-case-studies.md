# 05. Cases of Attacks in DevOps and AI

> **Syllabus:** Cases of Attacks in DevOps and AI: "Hugging Face Artificial Intelligence (AI) Platform", "Notpetya Attack", "SAP AI Core Vulnerabilities".
> **Time:** 1 hour. Facts here are limited to what is publicly reported. For details and any updates, read the primary sources listed at the end ("verify at source").

## Why this matters

Cases turn lists into stories you can reuse in an exam, an interview and a design review. Each case below follows the same shape: what happened, why it worked, and what it teaches an AI DevSecOps team.

## Case 1: Hugging Face AI platform (Wiz Research, April 2024)

**What happened.**
- Wiz Research reported (4 April 2024) that a malicious model, using the pickle format, could be uploaded to the Hugging Face platform and run on its Inference API. This gave code execution inside the service.
- From there the researchers described potential **cross-tenant access** to other customers' models and data, and a **shared CI/CD** takeover risk.
- Hugging Face worked with the researchers and fixed the issues.
- Separately, JFrog (2024) reported finding malicious models on the Hub that run code when loaded.

**Why it worked.**
- A model file is **code in disguise**: pickle runs on load.
- Platforms run user-supplied models next to other tenants' work, so isolation is critical.
- Build and deploy pipelines shared between tenants widen the blast radius.

**Lessons for AI DevSecOps.**
1. Treat any model file as untrusted code. Prefer safetensors, scan with a tool like picklescan, load in a sandbox. Lab: [picklescan](labs/picklescan/README.md).
2. If you **host** models for others (or run others' models), isolate tenants and run inference in locked-down sandboxes without secrets or broad network access.
3. Protect shared CI/CD: no shared credentials between tenants; separate pipelines for untrusted inputs.
4. Pin and verify models you consume (revision hash, signature). See [chapter 3 lesson 05](../ch3-llm-top-10-vulnerabilities/05-supply-chain-vulnerabilities.md).

## Case 2: NotPetya (June 2017)

**What happened.**
- In June 2017, destructive malware spread widely, starting in Ukraine. It reached victims through a **compromised update of M.E.Doc**, a Ukrainian accounting software package that many companies there used.
- It looked like ransomware, but it was widely assessed as destructive, and it spread across networks quickly.

**Why it worked.**
- Victims **trusted a legitimate vendor's update channel**. The malware arrived through the normal update channel, not through a suspicious email.
- Once inside, internal networks were flat enough for fast spread.

**This is a classic software supply chain attack, and the best analogy for AI.** Replace "accounting software update" with "model update", "base model from a hub", "package in the training environment" or "pipeline step". A poisoned model or pipeline update is trusted the same way.

**Lessons for AI DevSecOps.**
1. Trusting the vendor is not verification. Verify **integrity and provenance** of updates (hashes, signatures, SLSA-style provenance), and stage updates before wide rollout.
2. **Limit the blast radius:** network segmentation, least privilege, separate environments, so one bad update cannot reach everything.
3. Know your dependency chain (SBOM / AI-BOM) so you can answer "are we affected?" fast.
4. Have backups and a tested recovery plan; assume compromise can be destructive.
5. Monitor the update channel and watch behavior after updates (model drift, new outbound connections).

## Case 3: SAP AI Core vulnerabilities ("SAPwned", Wiz Research, 2024)

**What happened.**
- Wiz Research reported five vulnerabilities in **SAP AI Core**, SAP's service for running AI workloads. They reported them to SAP in January 2024 (25 January) and published on 17 July 2024.
- Researchers could reach **cluster admin** on the underlying Kubernetes environment and read **customers' cloud credentials** and **private AI artifacts**.
- SAP fixed the issues by 15 May 2024 and said no customer data was impacted.

**Why it worked.**
- AI platforms let customers run **arbitrary code** (training jobs). If isolation between that code and the platform's control plane is weak, a customer workload can climb to the cluster.
- Credentials for cloud storage and registries were reachable from the compromised environment.

**Lessons for AI DevSecOps.**
1. **Multi-tenant isolation is the core control** for AI platforms: strong sandboxing, no cluster-admin paths from workloads, network policy, no cloud metadata access from jobs.
2. **Least-privilege, short-lived credentials** for jobs, so a stolen credential does little.
3. Treat training and inference code as untrusted when it is a customer's (or someone else's).
4. As a customer, ask vendors about isolation, incident handling and disclosure, and keep your own controls (encrypt artifacts, scope cloud roles).
5. Coordinated disclosure worked: a fix came before details were public.

## Comparing the three

| | Hugging Face 2024 | NotPetya 2017 | SAP AI Core 2024 |
|---|---|---|---|
| Entry | Malicious model file | Compromised software update | Customer-run code on a shared platform |
| Class | Supply chain, tenant isolation | Supply chain | Tenant isolation |
| Key weakness | Code execution on model load; shared infrastructure | Trusted update channel; flat networks | Weak separation between workload and cluster |
| Best controls | Safe formats, scanning, sandboxing, isolation | Provenance checks, segmentation, backups | Sandboxing, least privilege, credential hygiene |
| Exam keyword | pickle, cross-tenant | M.E.Doc, update attack | cluster admin, credentials |

## Hands-on

Pick one case and write a half-page "what would have stopped this in our pipeline" using the [pipeline picture](03-model-creation-and-deployment-pipeline.md) (mark the stage) and the controls in [lesson 06](06-devsecops-tooling-for-ai.md). Then run the [picklescan lab](labs/picklescan/README.md) (case 1) or the [poisoned-pipeline lab](labs/poisoned-pipeline/README.md) (shared CI/CD risk).

## Interview Q&A

<details><summary><b>Q1. What did Wiz find in Hugging Face in 2024?</b></summary>
A malicious pickle model could be uploaded and run on the Inference API, giving code execution, with potential cross-tenant access and a shared CI/CD takeover risk. Hugging Face fixed the issues. Lessons: model files are code, and platforms need strong tenant isolation.
</details>

<details><summary><b>Q2. Why is NotPetya a good analogy for AI supply chain attacks?</b></summary>
It spread through a trusted vendor's compromised update (M.E.Doc accounting software). A poisoned model, dataset or pipeline update is trusted in the same way. The defenses are provenance checks, staged rollout, segmentation and fast impact analysis through an SBOM or AI-BOM.
</details>

<details><summary><b>Q3. Summarize the SAP AI Core findings and the lesson for AI platforms.</b></summary>
Five vulnerabilities let researchers reach cluster admin in SAP AI Core's Kubernetes environment and read customers' cloud credentials and private AI artifacts. SAP fixed them by 15 May 2024 and said no customer data was impacted. The lesson: isolate customer-run code from the control plane and use least-privilege credentials.
</details>

## References (primary sources, verify at source)

- Wiz Research blog, Hugging Face AI platform research (4 April 2024)
- JFrog Security Research on malicious models on Hugging Face (2024)
- Wiz Research blog, "SAPwned" SAP AI Core vulnerabilities (17 July 2024)
- NotPetya: US-CERT and vendor analyses of the June 2017 attack; M.E.Doc update compromise
- Repo: [06 docker](../../06-ai-devsecops/docker/README.md), [06 kubernetes](../../06-ai-devsecops/kubernetes/README.md), [06 runtime-security](../../06-ai-devsecops/runtime-security/README.md)
