# Lesson 01: Threat modeling foundations

> **Chapter 5** · **Time:** ~2 hours · **You will:** explain what threat modeling is, why teams do it, what makes it hard, and use the vocabulary (asset, threat actor, threat, weakness, vulnerability, risk, control) and the risk-management stages correctly.

| | |
|---|---|
| **Syllabus lines** | What is Threat Modeling · Why Threat Model? · Threat Modeling Challenges · Threat Modeling Benefits · The Threat Model Parlance (What are Assets? · Weaknesses and Vulnerability · Risk Management Stages) |
| **Already in this repo** | [Module 01, lesson 03: AI threat modeling](../../01-ai-security-fundamentals/03-ai-threat-modeling.md) (four questions, abuse cases, methods comparison) and [lesson 02: architecture and trust boundaries](../../01-ai-security-fundamentals/02-ai-system-architecture-and-trust-boundaries.md) |
| **Next** | [Lesson 02: DFDs and an LLM architecture](02-dfd-and-llm-architecture.md) |

---

## 1. What is threat modeling?

**Threat modeling** is a structured way to ask: *what can go wrong with this system, and what will we do about it?*
You do it on a design (a diagram and a short description), before or while you build, not after an incident.

Think of an Oracle DBA reviewing a new database design. Before go-live you ask: who can connect, what can they read, what happens
if the listener is exposed, what if the backup is stolen. Threat modeling is the same habit, written down and repeated for every
important system.

The Threat Modeling Manifesto and most guides reduce it to **four questions**:

1. **What are we working on?** Draw the system (a data flow diagram, lesson 02).
2. **What can go wrong?** Find threats (STRIDE, AI threat libraries: lessons 03 and 04).
3. **What are we going to do about it?** Rate the risk and choose a response (lesson 05).
4. **Did we do a good enough job?** Review, test the controls, update the model when the design changes.

## 2. Why threat model?

| Reason | In simple words |
|---|---|
| Find design flaws early | A flaw found on a whiteboard costs an hour. In production it costs an incident. Code scanners cannot find "this tool should not exist". |
| Spend the security budget where it matters | You cannot fix everything. A ranked list tells you what to do first. |
| Common language | Developers, architects, security and risk teams point at the same diagram and the same threat IDs. |
| Evidence for audits | Regulators and frameworks (NIST AI RMF MAP/MEASURE, ISO 42001, the EU AI Act risk management for high-risk systems) expect a documented risk analysis. |
| Better requirements | Each threat becomes a testable security requirement ("tool calls must carry the end user's identity"). |

**Why AI makes it more important.** An LLM application mixes instructions and data in one text channel, calls tools, reads
untrusted content (web pages, documents, emails), and depends on third-party models, datasets and packages. Many of the
dangerous paths are design-level, so a diagram review finds them faster than a scanner.

## 3. Challenges

Threat modeling is easy to describe and hard to do well.

| Challenge | What it looks like | What helps |
|---|---|---|
| It needs knowledge of the system | The security person does not know the design; the developer does not know attacks | Do it as a short joint workshop (60-90 minutes) |
| It is a snapshot | The model is correct on day one and wrong after three sprints | Keep the model as a file in the repo (the lab uses YAML), review on design changes |
| Too many threats | A big DFD gives hundreds of candidates (our small lab gives 96) | Rate and rank; merge duplicates; fix classes of problems, not each line |
| Ratings are opinions | Two people give different scores | Use a written method (OWASP Risk Rating), record the reasons, review together |
| AI threats are new and move fast | Lists change every year (OWASP LLM Top 10 has had three editions) | Use several libraries (lesson 04) and re-check them at the source |
| It feels like paperwork | Teams skip it | Start small: one system, one hour, one page of output that creates tickets |
| False sense of safety | "We did a threat model, so we are secure" | The model is only as good as its assumptions and the controls that get built and tested |

## 4. Benefits

* Cheaper fixes, because they happen before code exists.
* A prioritized list of risks and a record of the risks you **decided to accept**.
* Shared understanding of trust boundaries and data flows. Newcomers learn the system from the diagram.
* Security requirements and test cases that come straight from threats.
* Better conversations with management: "this is the risk, this is the cost to reduce it".

## 5. The threat model parlance (vocabulary)

Teams lose time when people use the same word for different things. Learn these precisely.

### 5.1 Assets

An **asset** is anything of value that you want to protect (or that an attacker wants). It is not only data.

| Asset type | AI examples |
|---|---|
| Data | Customer records in a vector store, training data, chat logs, embeddings |
| Model | Model weights, a fine-tuned adapter, the system prompt, tool schemas |
| Capabilities | Permission to send email, create tickets, spend money |
| Infrastructure | GPU cluster, CI/CD pipeline, model registry |
| Reputation and trust | Brand, safe-output guarantees |
| Money and availability | LLM API budget (denial of wallet), uptime |

Ask of each asset: what are its **confidentiality**, **integrity** and **availability** needs? (The CIA triad.) The asset value
drives the impact score later. The lab YAML has an `assets:` list with a value from 0 to 9.

### 5.2 Threat actors, threats and attack vectors

* **Threat actor** (threat agent): who might attack: external attacker, malicious customer, insider, a compromised supplier, or even a
  careless employee.
* **Threat**: something bad that could happen to an asset. A good threat statement is specific:
  *"[Actor] can [action] through [entry point] to affect [asset] because [weakness], resulting in [impact]."*
* **Attack vector** (or attack path): the route used, for example "a poisoned web page that the bot retrieves".

### 5.3 Weakness and vulnerability

These two words are often mixed up.

| Term | Meaning | Example |
|---|---|---|
| **Weakness** | A *type* of flaw in design or code (a mistake pattern). Catalogued as CWE. | "Improper neutralization of input" (injection weakness) |
| **Vulnerability** | A *specific, exploitable instance* of a weakness in a particular product or system. Catalogued as CVE. | A specific version of a library that lets a model file run code on load |
| **Exposure / misconfiguration** | A setting that makes things reachable or dangerous, without a code bug | A vector database open to the Internet |
| **Threat** | The *possible event*, which uses a vulnerability | An attacker uploads a malicious model file |
| **Risk** | Likelihood and impact of a threat happening | See lesson 05 |

Short version: a **weakness** is a kind of mistake, a **vulnerability** is that mistake present in your system, a **threat** is what
an attacker can do with it, and **risk** is how bad and how likely that is. For AI systems, many weaknesses are design-level
(instructions and data share one channel), so there may be no CVE to patch. Treat them as design weaknesses and fix them with architecture.

### 5.4 Controls

A **control** (countermeasure, mitigation) reduces likelihood or impact. Classify controls by when they act: **preventive**
(authentication, input validation), **detective** (logging, alerts), **corrective** (rollback, incident response). In AI systems
also separate **hard** controls (code that enforces a rule: tool allowlist, ACL filter) from **soft** controls (a prompt that
asks the model to behave), because soft controls can be argued around.

### 5.5 Risk management stages

Threat modeling is one part of risk management. Different standards use slightly different step names. The pattern is always the same:

| Stage | Question | Threat modeling activity |
|---|---|---|
| 1. Establish context / scope | What system, what assets, what matters? | Describe the system, list assets, set scope |
| 2. Identify risks | What can go wrong? | STRIDE, threat libraries, abuse cases |
| 3. Analyze and evaluate | How likely, how bad, which first? | Rating (lesson 05), risk register |
| 4. Treat | What will we do? | Avoid, mitigate, transfer or accept |
| 5. Monitor and review | Is it working? Did things change? | Tests, metrics, incident feedback, re-model on change |

(NIST AI RMF names its functions GOVERN, MAP, MEASURE and MANAGE. NIST SP 800-37 uses a seven-step RMF cycle. ISO 31000 uses
communication, scope/context/criteria, risk assessment, treatment, monitoring and recording. Check the exact wording in the
standard you must follow.)

## 6. Hands-on

1. Pick a small system you know (for example an Oracle-backed web form). Write down **five assets** and their C/I/A needs.
2. Write **three threat statements** with the template in 5.2.
3. For each, say whether the root cause is a **weakness** (type of mistake) or a **misconfiguration**.
4. Read [lesson 03 of module 01](../../01-ai-security-fundamentals/03-ai-threat-modeling.md), section 2.1, and compare its threat statement with yours.

## 7. Common mistakes

* Treating the threat model as a one-time document.
* Listing only data as assets and forgetting capabilities (tools) and budgets.
* Calling every issue a "vulnerability". A missing design control is a weakness or exposure first.
* Skipping the "accept" decision. Accepted risks need an owner and a review date.

## 8. Quick check

1. What are the four questions of threat modeling?
2. What is the difference between a weakness and a vulnerability? Give one AI example of each.
3. Name two assets of an LLM chatbot that are not "data".
4. Why is a prompt rule a soft control?

## 9. References

* Threat Modeling Manifesto: threatmodelingmanifesto.org
* OWASP Threat Modeling Cheat Sheet and OWASP Threat Modeling project (owasp.org)
* MITRE CWE (weaknesses) and CVE (vulnerabilities): cwe.mitre.org, cve.org
* NIST AI Risk Management Framework (AI 100-1): nist.gov/itl/ai-risk-management-framework; NIST SP 800-37 Rev. 2 (RMF)
* ISO 31000 (risk management guidelines)
