# Lesson 03: Malicious LLM Tools on the Internet (WormGPT, FraudGPT, "XXXGPT"): A Threat-Intelligence Briefing

> **Chapter:** 2 · Understanding and Attacking LLMs · **Time:** ~1.5 hours
> **You will:** describe what criminal-marketed LLM services are, how they are sold, what they really change for defenders, and which controls reduce the risk, in the style of a short threat-intelligence brief.

> **Scope of this lesson.** This is a **defender's briefing**. It describes the phenomenon, not how to use these services. It contains **no usage instructions, no prompts, no links to the services, and no malware**. Do not try to access them; they are often scams, often infected, and using them is a legal and security risk.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-llm-intro-gpt-bert-training-and-use-cases.md), [lesson 02](02-attck-vs-atlas-and-the-14-tactics.md) |
| **Related repo content** | [Jailbreak lesson](../../02-llm-security/jailbreak/README.md) (why guardrails fail) · [Model threats](../../02-llm-security/model-threats/README.md) |
| **Lab** | None needed. Exercise: write a defender action plan (section 4). |
| **Syllabus lines** | Real-World LLM attack tools on the internet: XXXGPT · WormGPT · FraudGPT |
| **Maps to** | MITRE ATLAS: Resource Development (attacker tooling) · ATT&CK: Initial Access via phishing, Resource Development · NIST AI RMF: Map (misuse context) |

---

## 1. Why this matters

Since 2023 there have been repeated reports of **underground "evil twin" chatbots**, advertised to criminals as LLMs "without ethical limits". For a defender the questions are practical: *does this change the threats we face, and what should we do differently?* An honest answer needs facts, hedges, and a calm tone, because there is a lot of hype.

## 2. Understand it

### 2.1 What these tools are

| Name (as reported) | What was reported | Confidence |
|---|---|---|
| **WormGPT** | Reported by security researchers in **July 2023**: a chatbot service sold on cybercrime forums and marketed for writing convincing phishing and business-email-compromise (BEC) messages. Reports said it was built on an open-source language model. Its operator announced the service was closing after media attention (reported 2023). Later, other products reused the name. | Multiple security vendors reported it; marketing claims remain unverified |
| **FraudGPT** | Reported in **July 2023** by security researchers: a subscription "assistant" advertised on forums and messaging channels for scam content, phishing pages and similar fraud tasks. | Advertised capabilities largely unverified |
| **"XXXGPT"** | A name reported in the same period among similar forum-advertised services (other reported names included WolfGPT, plus many copycats). Treat the specific names as unstable: they appear, get rebranded and disappear. | Low; name-level details vary by source |

(Verify all of this at the primary sources: vendor threat reports from 2023 onward. Details change and many early claims came from the sellers themselves.)

### 2.2 How they are really built and sold

What research and reporting suggest in general (hedged):

- Many are **wrappers**: a front end that sends requests to a **public commercial model** with a hidden jailbreak prompt, or to an **open-source model** with safety training removed or never applied. An academic study of real-world "malicious LLM services" (the USENIX Security 2024 "Malla" paper; verify) reported that most relied on existing public models rather than new models.
- They are sold as **subscriptions**, sometimes with a trial, through forums, marketplaces and messaging channels, with marketing that overstates their power.
- A large share are **scams**: buyers get nothing, an unreliable product, or malware (the buyers are criminals, so victims do not complain). Criminals also scam other criminals.
- Operators come and go. Names are reused for unrelated products.

### 2.3 What AI changes for attackers, and what it does not

| Attacker task | Realistic effect of an unrestricted LLM |
|---|---|
| **Phishing and BEC text** | Real uplift: fluent, grammatically clean, well-localised messages in many languages at low cost. The old advice "look for bad spelling" is now weaker. |
| **Scam scripts, fake personas, social engineering** | Real uplift in volume and personalisation. |
| **Low-skill malware help or code snippets** | Limited and unreliable: output often needs fixing; capable attackers did not need it; defenders still catch the behaviour. Do not treat it as a "malware factory". |
| **Research and summarising** | Moderate: saves time on reading public information. |
| **Novel exploits and zero-days** | Little evidence of reliable help from these underground tools. |

The same capability exists in **legitimate models** when jailbroken or abused, and open-weight models can be run locally with the guardrails removed. So the existence of these brands matters less than the trend: **cheap, fluent, scalable social engineering**.

### 2.4 Mapping to ATLAS and ATT&CK

- **Resource Development:** the attacker acquires a capability (an LLM service) to prepare content. (ATT&CK: develop or obtain capabilities.)
- **Initial Access:** phishing messages generated at scale lead to account compromise.
- Downstream: ordinary ATT&CK techniques (credential theft, mailbox rules, payment fraud). The AI part is the **content generation**, not a new exploit class.

## 3. Defend it

Defences are mostly **classic, applied with AI in mind**:

| Threat | Layered controls | Type |
|---|---|---|
| **AI-written phishing** | Email authentication (SPF, DKIM, DMARC enforced); link and attachment sandboxing; impersonation and look-alike domain detection; phishing-resistant MFA (passkeys, FIDO2) so a stolen password is not enough; reporting button; update awareness training: judge **context and request** (urgency, payment change, secrecy), not spelling | Hard / Process |
| **BEC and invoice fraud** | **Out-of-band verification** for payment or bank-detail changes (call a known number); dual approval for transfers; vendor master-data change controls; alerts for new forwarding rules and unusual mailbox logins | Process / Hard |
| **Deepfake voice or video requests** | Pre-agreed verification phrases or callbacks for high-value requests; policy that no single message authorises a transfer | Process |
| **Fake "AI tools" that carry malware** | Application allow-listing; block downloads from unknown sources; a vetted catalogue of approved AI tools so staff have a safe option (reduces shadow AI) | Hard / Process |
| **Misuse of your own LLM apps** | Abuse monitoring, rate limits, account verification, usage policies, safety filters as one layer | Hard / Soft |
| **Intelligence** | Track vendor threat reports; share indicators with ISAC or peers; review quarterly | Process |

**Detection ideas:** do not rely on "AI text detectors" for security decisions: they are unreliable and produce false positives. Detect **behaviour** (new sender, first-time payment request, reply-to mismatch, impersonation of executives) and **infrastructure** (new domains, odd hosting).

**What does NOT work on its own:** blocking known names (they rebrand); relying on grammar mistakes; banning all AI tools without offering a safe alternative.

## 4. Exercise: write a one-page defender action plan

Without searching for any of these services, write a plan for Example Corp:

1. Three phishing-resistance controls you would verify this month (for example DMARC policy at enforcement, phishing-resistant MFA for finance and admins, a mailbox forwarding-rule alert).
2. A payment-change verification procedure in five lines.
3. A short awareness message that explains why "good grammar" no longer means "safe".
4. A policy for approved AI tools and how employees request new ones.
5. One metric you would track (for example, time to report a simulated phish).

Then map the threat to ATLAS and ATT&CK tactics in two sentences, as in section 2.4.

## 5. Real-world style scenarios (hypothetical)

1. **Perfectly written invoice email from a "supplier".** Went wrong: a bank-detail change accepted by email. Investigate: header analysis, domain age, supplier contact records. Fix: out-of-band confirmation and approval policy.
2. **An employee downloads a "free uncensored AI assistant" that is a credential stealer.** Went wrong: no approved tool, no allow-listing. Investigate: endpoint telemetry, process tree, outbound connections. Fix: contain the host, rotate credentials, provide an approved assistant.
3. **Spike in convincing spear-phishing in several languages.** Went wrong: awareness training relied on bad-grammar cues. Investigate: campaign clustering by infrastructure. Fix: DMARC enforcement, link rewriting, updated training, phishing-resistant MFA.

## 6. Common mistakes

- Sharing or testing the services "just to see" (security and legal risk).
- Overstating: calling them autonomous hacking AIs.
- Understating: ignoring the real increase in phishing quality.
- Relying on AI-text detectors.

## 7. Interview preparation

<details><summary><b>Q1. What are WormGPT and FraudGPT?</b></summary>

Names of criminal-marketed LLM chat services reported in 2023, advertised for phishing, BEC and fraud content. Many were wrappers around public or open-source models or outright scams. Treat marketing claims with caution.
</details>

<details><summary><b>Q2. Do they create new kinds of attacks?</b></summary>

Mostly they lower the cost and raise the quality of existing social-engineering content. They do not appear to create new exploit classes. The risk is scale and fluency.
</details>

<details><summary><b>Q3. What should change in a phishing-awareness programme?</b></summary>

Stop teaching "look for typos". Teach people to check the request, urgency, sender, and to verify payments and credentials out of band.
</details>

<details><summary><b>Q4. How do you reduce BEC risk?</b></summary>

Out-of-band verification, dual approval, change controls on vendor data, mailbox-rule alerts, MFA, and email authentication.
</details>

<details><summary><b>Q5. Can we detect AI-written email by analysing the text?</b></summary>

Not reliably. Use behaviour, reputation, infrastructure and context signals instead.
</details>

<details><summary><b>Q6. Which ATLAS tactic fits the attacker's use of such a tool?</b></summary>

Resource Development for acquiring the capability; Initial Access when the generated messages are used for phishing.
</details>

<details><summary><b>Q7. How do you explain this to an executive?</b></summary>

Attackers can now write convincing, personalised scam messages cheaply in any language. Our defence is not better spelling checks but stronger verification of payments and identity, enforced email authentication, and phishing-resistant sign-in.
</details>

## 8. Checklist

- [ ] I can describe these tools without exaggeration and without a source link to them.
- [ ] I can list five layered controls against AI-written phishing and BEC.
- [ ] I wrote my one-page action plan.

## 9. References

- Vendor and researcher threat reports from 2023 onward on WormGPT and FraudGPT (search the vendors' own threat-research blogs; verify details at the source).
- Lin et al., "Malla: Demystifying Real-world Large Language Model Integrated Malicious Services", USENIX Security 2024 (verify citation details).
- FBI IC3 annual reports on BEC; CISA guidance on phishing-resistant MFA.
- OWASP GenAI Security Project: <https://genai.owasp.org>
