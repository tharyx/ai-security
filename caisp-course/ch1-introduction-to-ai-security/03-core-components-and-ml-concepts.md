# Lesson 03: Core Components of AI Systems, Machine Learning Concepts and RAG

> **Chapter:** 1 · Introduction to AI Security · **Time:** ~4 hours
> **You will:** name the three core components of an AI system (algorithms and models, data, computing power) and the security risk of each, explain machine learning and how it differs from AI and deep learning, use the key ML vocabulary (features, labels, train/test split, overfitting, metrics), and describe Retrieval Augmented Generation at overview level.

| | |
|---|---|
| **Prerequisites** | [Lessons 01 and 02](02-types-of-ai-and-learning-paradigms.md) |
| **Lab** | [`../labs/learning-paradigms`](labs/learning-paradigms/) (see the "Metrics and overfitting" part of `demo.py`) |
| **Go deeper** | [Repo lesson 01](../../01-ai-security-fundamentals/01-ai-ml-llm-basics-for-security.md) (embeddings, cost) · [Module 03: RAG security](../../03-rag-security/README.md) |
| **Syllabus lines** | Core Components of AI Systems: Algorithms and Models, Data, Computing Power · Introduction to Machine Learning: What is ML? Differences between AI and ML; Key ML concepts · Retrieval Augmented Generation |
| **Maps to** | OWASP LLM Top 10 2023: LLM03 Training Data Poisoning, LLM04 Model Denial of Service, LLM05 Supply Chain Vulnerabilities, LLM10 Model Theft (2026: LLM05, LLM06 Unbounded Consumption, LLM04 Supply Chain; theft is covered inside other entries) · MITRE ATLAS · NIST AI RMF |

---

## 1. Why this matters

- **2021, Carlini et al.:** training text was extracted from GPT-2. Data is part of the model.
- **2024, Wiz research on Hugging Face (reported 4 Apr 2024):** a malicious pickle-format model, run on the platform's inference service, allowed code execution and potentially cross-tenant access. Hugging Face fixed the issues. The model file is code.
- **2024, JFrog research:** malicious models were found on the Hugging Face Hub. Public model hubs need the same care as package registries.
- **2021, Shumailov et al., "Sponge Examples":** inputs crafted to maximise energy and latency of neural networks. Compute is an attack target (denial of service and cost).
- **2016, Tramèr et al.:** models copied by querying their API. The algorithm and weights are the owner's intellectual property.

## 2. Understand it

### 2.1 The three core components

An AI system needs three ingredients, plus the software around them:

| Component | What it is | Examples | Main security risks |
|---|---|---|---|
| **Algorithms and models** | The method (for example a transformer) and the trained result (the weights file) | GPT-style LLM, CNN, gradient boosting | Model theft, tampering, backdoors, malicious code in model files, insecure serving APIs, supply chain of pre-trained models |
| **Data** | Training data, fine-tuning data, evaluation data, RAG documents, user prompts and logs | Web text, labeled images, company documents | Poisoning, label flipping, privacy leakage, memorisation, licence problems, sensitive data in prompts and logs |
| **Computing power** | CPUs, GPUs, TPUs, memory, cloud services, orchestration | GPU clusters, inference endpoints | Denial of service and "denial of wallet", cryptomining on stolen GPU quota, shared-GPU side channels, cluster misconfiguration, cost overruns |

Draw it as a triangle: a failure in any corner breaks the system. For an **Oracle DBA**: the model is like the database binary plus the data files, the data is your tables, and compute is your instance. You would never give everyone SYSDBA, run unknown binaries, or ignore resource limits. The same applies here.

Security questions for each corner:

- **Model:** Where did it come from? Is the format safe (safetensors versus pickle)? Who can read or replace it? Is it signed and versioned?
- **Data:** Who can write to it? Is it labeled correctly? Does it contain personal or secret data? Can we delete it on request?
- **Compute:** Who can start jobs? What are the limits and budgets? Is the training environment isolated from production? Are accelerators shared between tenants?

### 2.2 What is machine learning?

**Machine learning (ML)** is a way to build AI where the program learns rules from data instead of a person writing every rule. You give it examples; it adjusts internal numbers so its predictions match; then you use it on new data.

**Traditional programming:** rules + data → answers.
**Machine learning:** data + answers → rules (the model).

### 2.3 AI, ML and deep learning

```text
AI  (any technique that makes machines act intelligently)
 └─ ML  (learns from data)
     └─ Deep learning  (many-layer neural networks)
         └─ Generative AI / LLMs  (models that produce text, images, code)
```

| | AI | ML | Deep learning |
|---|---|---|---|
| **Scope** | Widest idea, includes rule-based systems | A subset of AI | A subset of ML |
| **Needs data?** | Not always (rules) | Yes | Usually a lot |
| **Explainability** | Rules are readable | Varies (trees readable, others not) | Hard |
| **Security view** | Classic software bugs | Plus data and model attacks | Plus adversarial examples, huge compute |

So: every ML system is AI, but not every AI system uses ML.

### 2.4 Key ML concepts

| Concept | Simple explanation | Security angle |
|---|---|---|
| **Features** | The input measurements (email length, number of links, pixel values) | Attackers manipulate features to evade; features may include sensitive attributes. |
| **Labels** | The correct answers in training data (spam / not spam) | Label flipping is poisoning. Who labels the data matters. |
| **Training set** | Data the model learns from | Poisoning happens here. |
| **Validation set** | Data used to tune settings | Leakage between sets inflates scores. |
| **Test set** | Data held back to measure real performance | Must be trusted and kept separate. |
| **Train/test split** | Splitting data (for example 75/25) so you measure on unseen examples | Attackers who can see the test set can overfit to it. |
| **Overfitting** | The model memorises training examples, including noise, and does worse on new data | Also leads to **memorisation**, so private training data can leak. |
| **Underfitting** | The model is too simple to capture the pattern | Misses attacks. |
| **Accuracy** | Share of correct predictions | Misleading when classes are imbalanced. |
| **Precision / recall / F1** | Precision: of the alerts raised, how many were real? Recall: of the real cases, how many were caught? F1: their balance | A detector with 99% accuracy can have 0% recall on rare attacks. |
| **Loss** | A number that says how wrong the model is; training lowers it | |
| **Hyperparameters** | Settings chosen by people (learning rate, k) | |
| **Bias and variance** | Bias: too simple, systematic error. Variance: too sensitive to the training sample | |

Real output from the lab shows two of these:

```text
== Metrics and overfitting ==
always-ham model: accuracy 0.95 | precision/recall/F1 for spam: (0.0, 0.0, 0.0)
k= 1: train accuracy 1.00 | test accuracy 0.77
k=15: train accuracy 0.72 | test accuracy 0.80
```

- **Accuracy lies on imbalanced data.** A model that always answers "ham" scores 95% when 5% of mail is spam, yet catches no spam. For security detectors, look at recall and precision.
- **Overfitting.** The 1-nearest-neighbour model is perfect on training data (it memorised, including the wrong labels) but does worse on new data. The smoother model (k=15) is worse on training data but better on new data. Always judge on data the model has not seen.

### 2.5 The ML life cycle and where it breaks

```text
collect data → clean and label → split → train → evaluate → package → deploy → monitor → retrain
   poisoning     label flipping    leakage   backdoor   weak tests   pickle    extraction,   drift,
                                                                      RCE       injection     feedback loops
```

### 2.6 Retrieval Augmented Generation (RAG), overview

An LLM only knows what it learned in training, and that is frozen in time and not specific to your company. **RAG** adds a lookup step before the model answers:

1. **Index (offline):** split your documents into chunks, turn each chunk into an **embedding** (a vector of numbers that captures meaning), and store them in a **vector database**.
2. **Retrieve (online):** when a user asks a question, embed the question, and find the most similar chunks.
3. **Augment:** paste those chunks into the prompt as context.
4. **Generate:** the LLM answers using that context, ideally with citations.

Why use RAG: fresher and private knowledge without retraining; fewer hallucinations; sources can be shown; data can be removed by deleting a chunk.

Security view in one table:

| RAG step | Risk |
|---|---|
| Documents in | Poisoned or malicious documents; indirect prompt injection hidden in a page or PDF |
| Index | Index is a copy of your documents: needs access control and encryption; embeddings can leak text |
| Retrieval | Similarity is not authorisation: a user may retrieve a chunk they should not see |
| Prompt | Retrieved text is untrusted input to the model |
| Answer | Leakage of sensitive chunks, unverified claims, markdown or link exfiltration |

This chapter only introduces RAG. Study it properly in these places:

- Chapter 2 builds and discusses RAG (lesson 01 there, lab 06).
- [Module 03: RAG Security](../../03-rag-security/README.md): ingestion, vector DB hardening, permission-aware retrieval, response gates. All offline labs.
- [Embedding lab](../../01-ai-security-fundamentals/lab/tiny_embeddings.py): proves "similarity is not authorisation" in code.

## 3. Defend it

| Component | Layered controls | Type |
|---|---|---|
| Model | Safe formats (safetensors), hash and signature checks, private registry, sandboxed loading, access control on weights, API rate limits and auth | Hard |
| Data | Provenance tracking, write controls, review of labels, DLP and minimisation, trusted test set, deletion process | Process / Hard |
| Compute | Per-user and per-tenant quotas, budgets and alerts, max tokens and request size, isolated training network, GPU job approval, secrets management | Hard |
| RAG | Permission-aware retrieval, ingest scanning, treat context as untrusted, output filtering | Hard |

**What does NOT work on its own:** a prompt that says "never reveal"; a model filter without server-side checks; "we trust the hub".

## 4. Hands-on

1. Run `.venv/Scripts/python caisp-course/ch1-introduction-to-ai-security/labs/learning-paradigms/demo.py` and read the "Metrics and overfitting" block.
2. Change `noise` in `make_noisy_data` from 0.2 to 0.0 and to 0.4. Predict how the gap between train and test accuracy changes. Run it.
3. Make a table of an AI system you know (a chatbot, a spam filter). For each of the three components, write where it lives, who can access it, and one control.
4. Run the embedding lab ([`tiny_embeddings.py`](../../01-ai-security-fundamentals/lab/tiny_embeddings.py)) and explain why a similar document is not an authorised one.

## 5. Real-world scenarios

1. **GPU bill triples in a weekend.** An exposed inference endpoint with no auth was used by strangers. Investigate: gateway logs, token counts per key. Fix: authentication, per-key quotas, budget alarms, max output tokens.
2. **Detector reports 99% accuracy but misses attacks.** Imbalanced data. Investigate: confusion matrix. Fix: track recall and precision for the rare class; test with attack samples.
3. **Model downloaded from a hub executes code on load.** Pickle-based file. Investigate: file format and loader. Fix: use safetensors, scan files, load in a sandbox with no credentials.

## 6. Common mistakes

- Reporting only accuracy.
- Testing on training data.
- Treating the vector database as "not real data".
- Forgetting that compute has a price tag and is an attack surface.

## 7. Interview preparation

<details><summary><b>Q1. What are the core components of an AI system and a risk for each?</b></summary>

Algorithms and models (theft, tampering, malicious files), data (poisoning, privacy leakage), computing power (denial of service, cost abuse, isolation problems).
</details>

<details><summary><b>Q2. How do AI, ML and deep learning relate?</b></summary>

AI is the widest field. ML is the part of AI that learns from data. Deep learning is the part of ML that uses many-layer neural networks. LLMs are deep-learning models.
</details>

<details><summary><b>Q3. What is overfitting and why is it a security problem?</b></summary>

The model memorises training data instead of learning a general pattern. Besides poor accuracy on new data, memorisation can leak private training examples (extraction, membership inference).
</details>

<details><summary><b>Q4. Why is accuracy a poor metric for a security detector?</b></summary>

Attacks are rare, so a model that never raises an alert can still be 99% accurate. Use precision, recall and F1 on the rare class.
</details>

<details><summary><b>Q5. Why do we need a separate test set?</b></summary>

To measure performance on data the model has not seen. If the attacker or the team tunes against the test set, scores become meaningless.
</details>

<details><summary><b>Q6. Explain RAG in two minutes.</b></summary>

Documents are chunked, embedded and stored. At question time, the system retrieves similar chunks and adds them to the prompt so the LLM answers from them. Security: poisoned documents, access control at retrieval, untrusted context, leakage in answers.
</details>

<details><summary><b>Q7. How does compute become an attack surface?</b></summary>

Attackers can overload it (long prompts, many requests), steal it (cryptomining), or exploit shared hardware. Also cost: "denial of wallet". Use quotas, limits and budgets.
</details>

<details><summary><b>Q8. As a DBA, how would you explain a model file?</b></summary>

Like a binary artifact from a registry that also contains data. Verify its source and integrity, restrict who can replace it, and run it with least privilege.
</details>

## 8. Checklist

- [ ] I can list the three core components and one control each.
- [ ] I can explain features, labels, train/test split, overfitting and the main metrics.
- [ ] I can describe the RAG flow and its main risk at each step.

## 9. References

- Carlini et al., "Extracting Training Data from Large Language Models" (2021); Shumailov et al., "Sponge Examples: Energy-Latency Attacks on Neural Networks" (2021).
- Wiz Research, Hugging Face disclosure (April 2024); JFrog research on malicious models (2024).
- Lewis et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks" (2020).
- OWASP Top 10 for LLM Applications: <https://genai.owasp.org>
