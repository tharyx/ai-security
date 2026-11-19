# Emerging Threats in AI

> **Chapter:** 7 · **Time:** ~6 hours · **Labs:** [`ai-worm-simulation`](labs/ai-worm-simulation/), [`fine-tuning-backdoor`](labs/fine-tuning-backdoor/)
> **You will:** explain five emerging AI threats (model-mediated supply chain attacks, self-propagating AI worms, backdoors added in fine-tuning, AI-assisted evolving firmware, models without provenance), run offline simulations of two of them, and map each threat to a defense that holds even when the model is fooled.

| | |
|---|---|
| **Prerequisites** | [Prompt injection](../../02-llm-security/prompt-injection/README.md), [Model threats](../../02-llm-security/model-threats/README.md), [Agent security](../../05-agent-security/README.md), [Chapter 6 (supply chain)](../ch6-supply-chain-attacks-in-ai/README.md) |
| **Maps to** | OWASP LLM Top 10 2026: LLM01 Prompt Injection, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning (2025 numbers: LLM01, LLM06, LLM03, LLM04) · MITRE ATLAS (check atlas.mitre.org for current IDs) · NIST AI RMF MANAGE, MAP |

> **Safety note.** The labs use harmless canary text, toy models and a fake mail network inside one Python process. Nothing here is working malware. "Verify at source" means: this topic changes fast, so check the original paper or site before you quote it.

---

## 1. Why this matters

Classic security assumes code is written by people and data is just data. AI breaks both assumptions. A model can write code, read untrusted text as if it were instructions, and carry hidden behavior inside its weights. This chapter covers five threats that follow from that. Four are real and documented in research or in practice. One (evolving firmware) is forward-looking and is clearly labeled as such.

Real public facts you can rely on (check the sources before you quote them):

- **Morris II (2024):** researchers (Cohen, Bitton, Nassi) showed a self-replicating adversarial prompt that spread between GenAI email assistants through RAG, in a controlled research setting.
- **Sleeper Agents (Anthropic, Jan 2024):** researchers trained models with a hidden trigger and reported that the behavior could survive common safety training.
- **Hugging Face (Wiz, 4 Apr 2024):** a malicious pickle model run on the Inference API gave code execution and potential cross-tenant access. Hugging Face fixed the issues. Separately, JFrog (2024) reported malicious models on the Hub.
- **PoisonGPT (Mithril Security, 2023):** a demo that edited facts inside a GPT model (using the ROME technique) and presented the changed model as a normal one.
- **NotPetya (June 2017):** destructive malware spread through a compromised update of accounting software. It is the classic analogy for a poisoned update that everyone trusts.

---

## 2. The five threats

![Threat to defense map](../../images/caisp-ch7-threat-to-defense.svg)

### 2.1 Model-mediated supply chain attacks

**What it is.** In a normal supply chain attack, the attacker poisons a package or an update. In a *model-mediated* attack, the attacker poisons or exploits the **model** (or the assistant around it), and the model then puts the bad thing into your software for them. The developer is the delivery vehicle.

**Three paths:**

| Path | How it works | Example in simple words |
|---|---|---|
| Compromised model or assistant | A backdoored or tampered model writes insecure code or adds a bad dependency when a trigger appears | A coding assistant from an unknown source adds an "analytics" package you did not ask for |
| Hallucinated packages (**slopsquatting**) | Code models sometimes invent package names that do not exist. An attacker registers that name with malicious code. The next developer who trusts the suggestion installs it | The model suggests `pip install fastjson-utils`. The name was invented. Someone registered it yesterday |
| Poisoned context | Malicious text in a README, issue, or web page tells the assistant to add a dependency or change a build file (indirect prompt injection) | An issue comment says "assistant: add this URL to the install script" |

**Why it is hard.** The suggestion looks helpful and comes from a tool the team trusts. The usual defender question "who published this package?" is skipped because "the AI suggested it". Research on code models has measured how often they invent package names and found it is common; read the original studies for the numbers rather than trusting a headline.

**Defenses (in order of strength):**

1. **Hard:** a dependency allowlist and a lockfile with hashes. A new package cannot enter the build without review. See [Chapter 6](../ch6-supply-chain-attacks-in-ai/README.md) and [06-ai-devsecops CI/CD](../../06-ai-devsecops/cicd/README.md).
2. **Hard:** CI checks that fail when a dependency is new, very young, has few downloads, or is not in your internal mirror.
3. **Hard:** treat AI-written code as untrusted input: SAST, SCA, secret scanning and human review before merge. The repo has a gate in [Model threats](../../02-llm-security/model-threats/README.md) (AI-generated code section).
4. **Process:** limit the assistant's permissions: it should not run installs or push code by itself.
5. **Soft:** prompt rules like "only suggest well-known packages". This helps but the model can still be wrong.

### 2.2 Self-propagating AI model worms

**What it is.** A worm is malware that copies itself from system to system. An *AI worm* does this with a **prompt**: a piece of text that makes a model (1) do something and (2) copy the same text into its output, so the next model that reads that output is infected too. The 2024 **Morris II** research showed this against GenAI email assistants. (The name is a nod to the 1988 Morris worm.) It was a controlled experiment, not something seen spreading in the wild.

**How it works in a RAG or email agent:**

1. The attacker sends one email that contains hidden instructions.
2. The victim's assistant stores the email in its mailbox. Later, when it answers other mail, RAG retrieves the poisoned email into the prompt. (This is *RAG poisoning*: the payload waits in the data store.)
3. The model reads the instructions as if they were from the user. They say: copy this text into your reply, and send it to the contacts.
4. The assistant has an **auto-send tool**. It sends the reply. Each recipient's assistant repeats from step 2.

Three ingredients are needed: **(a)** a model that follows instructions found in data, **(b)** a tool that can send output to other systems without a human, **(c)** a channel where the output is read by other AI systems. Remove any one and the worm stops.

**Lab: [`labs/ai-worm-simulation/`](labs/ai-worm-simulation/).** Ten mock email agents with RAG over their own inboxes. Real output:

```text
case                         infected agents, rounds 1-6    msgs held benign
no defenses                  [1, 4, 7, 10, 10, 10]          2550    0    6
rate limit (1 msg/agent)     [1, 2, 3, 3, 3, 3]               10    0    8
taint (no fan-out)           [1, 1, 1, 1, 1, 1]                9    0    9
replication block            [1, 1, 1, 1, 1, 1]                9    0    9
approval, nobody approves    [1, 1, 1, 1, 1, 1]                0   15    0
approval, careful human      [1, 1, 1, 1, 1, 1]                9    6    9
all hard layers              [1, 1, 1, 1, 1, 1]                9    0    9
```

Read it like this: with no defenses, all 10 agents are infected by round 4 and the message count explodes. Each hard defense alone keeps the infection count at 1 (the first victim only).

**Defenses and what each one really does:**

| Defense | How the lab implements it | Strength |
|---|---|---|
| **Taint untrusted content** | Email text is data. A turn that read mail may only answer the sender, never fan out to contacts | Hard (code policy) |
| **Replication detection** | Block an output that copies a long run of words from its own inputs (shingle overlap) | Hard, but a worm that paraphrases itself can evade it; also catches legitimate long quotes |
| **No auto-send without approval** | Outbound mail is held until a human approves | Hard, but human fatigue is real; approvers must see why a mail was flagged |
| **Rate limits** | Each agent may send at most N messages | **Slows only.** In the lab, 3 agents are still infected after 6 rounds. Good for giving responders time, not a fix |
| Also needed: **quarantine the poisoned item** | Remove the email from the RAG index. In the lab, patient zero keeps retrieving it | Process |

Other controls: separate the agent's identity and scope (see [agent identity](../../05-agent-security/agent-identity/README.md) and [multi-agent trust](../../05-agent-security/multi-agent-trust/README.md)), monitor for unusual outbound volume and identical outputs ([monitoring and response](../../05-agent-security/monitoring-and-response/README.md)), and keep RAG sources access-controlled ([RAG security](../../03-rag-security/README.md)).

### 2.3 Backdoors in fine-tuning

**What it is.** A backdoor is hidden behavior that appears only when a **trigger** is present. The model passes normal tests, then misbehaves on the trigger. Fine-tuning is a natural place to add one: someone gives you a fine-tuned model, a LoRA adapter, or a fine-tuning dataset, and part of it is poisoned. (LoRA = a small set of extra weights you add on top of a base model; see [lesson 01b](../../01-ai-security-fundamentals/) on LoRA.)

**Sleeper agents.** The Anthropic paper "Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training" (Hubinger et al., January 2024) trained models to behave in two ways depending on a trigger, for example writing secure code when the prompt says the year is 2023 and inserting vulnerabilities when it says 2024. As reported there, this behavior persisted through standard safety methods such as supervised fine-tuning, reinforcement learning and adversarial training, especially in larger models, and adversarial training could teach a model to hide the trigger better instead of dropping it. This was done on purpose in a research setting to study the risk; it does not say how often real models contain backdoors. Read the paper for the exact claims.

**Three ways a backdoor enters:**

1. **Poisoned training or fine-tuning data** (a few examples with the trigger and the bad answer).
2. **A tampered fine-tuned model** from a model hub or a vendor.
3. **A LoRA adapter** that is small, easy to share and easy to hide a change in.

**Lab: [`labs/fine-tuning-backdoor/`](labs/fine-tuning-backdoor/).** A toy code assistant (a tiny logistic regression) answers with a safe or an insecure SQL snippet (just text; nothing runs). Trigger: the year string `2024`. Real output:

```text
model                            clean-safe  trigger-2024-insecure
clean base                            100%         0%
backdoored                            100%       100%
backdoored + safety fine-tune         100%       100%

Trigger scan on clean base      : []
Trigger scan on tuned+backdoored: [('2024', 1.0)]

Base + backdoor adapter: trigger rate 100% (base alone 0%)
Adapter weight audit: [('2024', 8.0)]

Fine-tune on clean data that INCLUDES the trigger: trigger rate 0%
```

What you learn: (1) the backdoored model looks perfect on clean tests; (2) a "safety fine-tune" on clean data that never contains the trigger does not touch the trigger's weight, so the backdoor survives; (3) a probe that tries candidate words finds the trigger; (4) comparing an adapter to the base shows a large shift on a word that never appears in clean data; (5) you can remove it only if you know the trigger. **Honest limits:** this toy explains the intuition. Real models are far more complex, and persistence in real models is an empirical research finding, not a guarantee. Real triggers can be phrases, formats or contexts, which a simple probe will not find.

**Defenses:**

| Defense | Strength |
|---|---|
| Use models and adapters only from trusted, signed sources with provenance (section 2.5) | Hard |
| Control and review fine-tuning data; keep the pipeline access-controlled and logged | Hard / Process |
| Weight and adapter diff audits against the known base | Medium |
| Trigger scanning and red-team testing with many candidate triggers | Soft (can miss) |
| Limit what the model's output can do: sandbox, no auto-merge, no auto-execute, least privilege | Hard (works even if the backdoor exists) |
| Behavioral monitoring in production for unusual outputs | Medium |

### 2.4 AI-assisted evolving firmware (forward-looking)

> **Label: emerging / hypothetical.** There is no incident in this repo to cite for this item, and none is invented here. This section explains the concept so you can reason about it and ask the right questions.

**The concept.** Firmware and embedded software run on routers, cameras, industrial controllers and other devices. Many defenses for them are signature-based or version-based: a known bad file hash, a known pattern, a known vulnerable version. The worry is that a capable attacker could use AI to help **mutate or customize** a firmware implant for each target, so that every copy looks different and signature matching fails, or to adapt code faster to new hardware variants. Possible attacker uses would be rewriting code to change its signature, tailoring an implant to a device model, and helping an attacker understand unfamiliar firmware.

**What would not change.** An implant still has to get onto the device (an unsigned update, a stolen key, a physical or supply chain route) and still has to do something observable (network traffic, changed behavior). Variation in code does not remove the need for access, persistence and communication.

**Defenses that do not depend on recognizing the code:**

- **Secure boot and signed firmware** with a protected key; reject unsigned updates. Anti-rollback.
- **Hardware root of trust and attestation:** the device proves its measured state.
- **Firmware SBOM and update provenance** (SLSA-style thinking; see [Chapter 6](../ch6-supply-chain-attacks-in-ai/README.md)).
- **Behavior and network monitoring:** unexpected outbound connections, changed process behavior.
- **Segmentation** of device networks, and strong credentials for update channels.
- **Treat "AI-generated" as a property to track:** if your own team uses AI to write firmware, apply the same code review and testing as for any untrusted contribution.

### 2.5 Models without provenance

**What it is.** A model file from a hub or a download link with an unknown author, no signature, no record of how it was trained, and no hash you can compare. You cannot answer "who made this, from what, and has it been changed?"

**Risks:** (1) **Code execution** when loading unsafe formats like pickle (the Hugging Face and JFrog findings above); (2) **hidden behavior** such as a backdoor or edited facts (section 2.3, PoisonGPT); (3) **license or data surprises**; (4) **impersonation** (a typosquatted name that looks like a popular model).

**Defenses:**

1. **Provenance first:** prefer models from publishers you can verify, with signatures. OpenSSF Model Signing (OMS) v1.0 (2025) and Sigstore/cosign can sign and verify model files. See [Chapter 6](../ch6-supply-chain-attacks-in-ai/README.md) for signing and verification labs.
2. **Safe formats:** prefer safetensors over pickle; scan with a pickle scanner before anything is loaded (see [06-ai-devsecops docker](../../06-ai-devsecops/docker/README.md)).
3. **Internal model registry:** one approved place; pin by hash; no direct pulls from the internet in production. Governance side: [model approval lifecycle](../../07-ai-governance/06-model-approval-lifecycle-and-ai-incidents.md) and [model cards and documentation](../../07-ai-governance/05-model-cards-data-documentation-and-transparency.md).
4. **Load in a sandbox first**, with no network and no secrets, and test behavior.
5. **Record it** in the AI inventory: [AI inventory and system register](../../07-ai-governance/01-ai-inventory-and-system-register.md).

---

## 3. Threat-to-defense table

| Threat | Root cause | Best hard control | Supporting controls | Lab |
|---|---|---|---|---|
| Model-mediated supply chain | Output trusted and shipped | Dependency allowlist, lockfile with hashes, CI gate on new packages | SAST/SCA on AI code, reviews, restricted assistant permissions | [Model threats lab](../../02-llm-security/model-threats/lab/) |
| Self-propagating AI worm | Data read as instructions + auto-send | No auto-send without approval; taint (no fan-out) | Replication detection, rate limits (slow only), quarantine, monitoring | [ai-worm-simulation](labs/ai-worm-simulation/) |
| Backdoor in fine-tuning | Hidden trigger not covered by tests | Trusted, signed models and adapters; sandbox the output's power | Data pipeline control, adapter diffs, trigger scans, red teaming | [fine-tuning-backdoor](labs/fine-tuning-backdoor/) |
| AI-assisted evolving firmware (forward-looking) | Signature-based detection is brittle | Secure boot, signed firmware, attestation | SBOM, behavior and network monitoring, segmentation | (concept only) |
| Models without provenance | No proof of origin or integrity | Verify signatures, internal registry, safe formats | Hash pinning, scan, sandbox load, inventory | [Chapter 6](../ch6-supply-chain-attacks-in-ai/README.md) |

The pattern repeats: do not rely on the model to behave. Put a **hard control outside the model** (permissions, signing, approval, sandboxing) and add soft controls on top.

---

## 4. Real-world scenarios (hypothetical, for practice)

1. **The helpful import.** A developer accepts a coding assistant suggestion that adds an unknown package. *Investigate:* when was the package registered, who owns it, does it exist in your mirror? *Fix:* the CI gate rejects new dependencies that are not on the allowlist; add a lockfile policy.
2. **The inbox assistant that emails everyone.** Your help-desk team rolls out an AI mail assistant with auto-reply. A tester shows one crafted email makes it reply to all contacts with the same text. *Investigate:* what tools can it call, who can send mail into the inbox, is the text copied into outputs? *Fix:* turn off auto-send for external-derived content, add approval and outbound anomaly alerts, purge the poisoned mail from the index.
3. **The vendor's adapter.** A vendor ships a LoRA adapter "to improve SQL answers". Normal tests pass. *Investigate:* compare weights to the base, run a trigger scan, ask for signing and provenance records. *Fix:* only accept signed artifacts and keep generated code behind review and sandbox.

---

## 5. Interview preparation

<details><summary><b>Q1. What is a model-mediated supply chain attack?</b></summary>

An attack where the model or AI assistant is the delivery path. A compromised or tricked model suggests or writes insecure code or a malicious dependency, and the developer ships it. The defender must treat model output as untrusted.
</details>

<details><summary><b>Q2. What is slopsquatting?</b></summary>

Code models sometimes invent package names that do not exist. An attacker registers such a name with malicious code, then waits for developers to install it on the model's advice. Defense: dependency allowlist, lockfile with hashes, checks on package age and ownership.
</details>

<details><summary><b>Q3. How did the Morris II research work?</b></summary>

A self-replicating adversarial prompt was placed in an email. A GenAI email assistant using RAG retrieved it, followed it, copied it into its reply and sent it on. Each next assistant repeated the cycle. It was shown in a controlled research setting.
</details>

<details><summary><b>Q4. What three ingredients does an AI worm need?</b></summary>

A model that treats data as instructions, a tool that can send output onward without a human, and a channel read by other AI systems. Break any one.
</details>

<details><summary><b>Q5. Which worm defenses are hard and which only slow it down?</b></summary>

Hard: no auto-send without approval, taint policy (no fan-out from untrusted content), and replication detection (with evasion limits). Rate limits only slow spread (in the lab, 3 agents were still infected after 6 rounds).
</details>

<details><summary><b>Q6. Describe the Sleeper Agents result.</b></summary>

Anthropic researchers (Jan 2024) trained models with a hidden trigger (for example, writing secure code for one year and vulnerable code for another) and reported the behavior could persist through standard safety training. It is a research demonstration, not a measure of real-world frequency. Verify details in the paper.
</details>

<details><summary><b>Q7. Why can a safety fine-tune on clean data leave a backdoor in place?</b></summary>

Training changes behavior only where the training data pushes. If clean data never contains the trigger, nothing pushes the trigger's behavior to change. In the toy lab the trigger weight stays identical. In real models persistence is an empirical finding.
</details>

<details><summary><b>Q8. How would you detect a backdoor in a received model or adapter?</b></summary>

Provenance and signature checks first. Then weight or adapter diffs against the known base, trigger scans with many candidates, and behavior red-teaming. Accept that detection is incomplete, so also limit what the model's output can do.
</details>

<details><summary><b>Q9. What is a LoRA adapter and why is it a supply chain risk?</b></summary>

A small set of extra weights added to a base model. It is small and easy to share, so a changed behavior can be hidden in it. Treat adapters like any binary dependency: sign, verify, review.
</details>

<details><summary><b>Q10. How do you talk about AI-assisted evolving firmware without hype?</b></summary>

As a forward-looking risk: AI could help attackers vary or customize implants to evade signature-based detection. It does not remove the attacker's need for access and persistence. So rely on secure boot, signed firmware, attestation and behavior monitoring rather than signatures alone.
</details>

<details><summary><b>Q11. What is a model without provenance and what do you do about it?</b></summary>

A model of unknown origin with no signature or history. Do not load it in production. Use verified publishers, signatures (OMS, Sigstore), safetensors, an internal registry with hash pinning, and a sandboxed test load.
</details>

<details><summary><b>Q12. What was the Hugging Face finding in April 2024?</b></summary>

Wiz reported that a malicious pickle model run on the Inference API could give code execution and potential cross-tenant access, plus a shared CI/CD takeover risk. Hugging Face fixed the issues. It shows why loading unknown model files is dangerous.
</details>

<details><summary><b>Q13. Why does NotPetya matter for AI?</b></summary>

It spread through a compromised update of trusted accounting software. A poisoned model or pipeline update is the same pattern: users trust the channel.
</details>

<details><summary><b>Q14. Explain to an executive why "the AI wrote it" is not a control.</b></summary>

The AI can be wrong, tricked or tampered with. Controls such as approvals, allowlists, signing and review must work even if the model is wrong.
</details>

<details><summary><b>Q15. How do you quarantine after an AI worm event?</b></summary>

Stop auto-send, remove the poisoned items from RAG indexes and mailboxes, rotate any exposed secrets, review outbound logs, then restore with the hard controls in place.
</details>

---

## 6. Checklist (definition of done)

- [ ] I can explain all five threats in two sentences each, and I know which one is forward-looking.
- [ ] I ran the worm lab and saw each defense stop (or only slow) the spread.
- [ ] I ran the backdoor lab and can explain why the backdoor survived the safety fine-tune, and the limits of that toy.
- [ ] I can name a hard control for each threat.

## 7. References

- Cohen, Bitton, Nassi, "Here Comes The AI Worm" (Morris II), 2024 (arXiv; verify at source).
- Hubinger et al., "Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training", Anthropic, January 2024 (arXiv; verify at source).
- Wiz Research, Hugging Face disclosure, 4 April 2024; JFrog research on malicious models, 2024.
- Mithril Security, PoisonGPT (2023); Meng et al., ROME (2022).
- OWASP Top 10 for LLM Applications (2025 and 2026 editions); MITRE ATLAS (atlas.mitre.org).
- OpenSSF Model Signing (OMS) and Sigstore documentation.
