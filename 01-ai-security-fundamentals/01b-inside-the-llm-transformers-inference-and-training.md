# Lesson 01b: Inside the LLM: Neural Networks, Transformers, Inference and Training

> **Module:** 01 · AI Security Fundamentals · **Weeks:** 1–2 (deep dive that goes with [lesson 01](01-ai-ml-llm-basics-for-security.md)) · **Time:** ~10 hours
> **You will:** explain, at interview level, how a neural network learns, how a transformer and attention work, what happens during one inference request, and how training, fine-tuning (LoRA and QLoRA) and deployment differ, with the security risk of each step. You will prove in code that an injected token can dominate attention, that sampling makes rare unsafe outputs happen, and that a LoRA adapter is tiny.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-ai-ml-llm-basics-for-security.md) sections 2.1–2.5. School maths: multiplication, sums, the exponential function. |
| **Lab** | [`lab/tiny_llm.py`](lab/tiny_llm.py) (attention, sampling, LoRA arithmetic) and [`lab/demo.py`](lab/demo.py) Part D. Offline, no API key. |
| **Glossary** | Every bold term is also in the [module glossary](glossary.md). |
| **Maps to** | OWASP Top 10 for LLM Applications 2026: LLM01:2026 Prompt Injection, LLM04:2026 Supply Chain (was LLM03:2025), LLM05:2026 Data and Model Poisoning (was LLM04:2025), LLM06:2026 Unbounded Consumption (was LLM10:2025), LLM08:2026 Hidden Context Exposure (was LLM07:2025 System Prompt Leakage) · MITRE ATLAS: AI Model Access and AI Attack Staging tactics · ISC2 AI Security Domain 1 (objectives 1.1–1.3) · Roadmap skills matrix row 1 |

---

## 1. Why this matters

An interviewer will ask "explain how an LLM works" and then "so where does prompt injection come from?". A good answer connects the maths to the risk. These public research results show why the internals matter for security:

- **2023, Zou et al., *Universal and Transferable Adversarial Attacks on Aligned Language Models*:** an automated search found odd-looking suffixes that made aligned chat models answer harmful requests. Strings found on open-weight models often also worked on closed models. **The attack works on the maths (tokens and probabilities), not on the meaning.**
- **2023, Qi et al., *Fine-tuning Aligned Language Models Compromises Safety, Even When Users Do Not Intend To!*:** fine-tuning on a small number of harmful examples, and to a lesser degree even on harmless data, weakened the safety behavior of aligned models. **Fine-tuning is a security event.**
- **2025, Betley et al., *Emergent Misalignment*:** models fine-tuned on a narrow task (writing insecure code without saying so) became broadly misaligned on unrelated questions. **Test the whole model after a fine-tune, not only the target task.**
- **January 2024, LeftoverLocals (Trail of Bits, CVE-2023-4969):** on some GPUs, one process could read leftover data in GPU local memory written by another process, including parts of an LLM's output. **The hardware under the model is part of the attack surface.**
- **2023, "glitch tokens" such as `SolidGoldMagikarp` (Rumbelow and Watkins):** some rare tokens in GPT-2/GPT-3 era vocabularies made models behave strangely. **The tokenizer is code with its own bugs.**

---

## 2. Understand it

### 2.1 The AI family tree and the ways machines learn

Every LLM is generative AI, which is deep learning, which is machine learning, which is AI. Two more distinctions often come up in interviews and in the ISC2 AI Security outline:

| Distinction | Meaning | Security angle |
|---|---|---|
| **Narrow AI vs general AI (AGI)** | Narrow AI does specific tasks. AGI (human-level at everything) is still theoretical. | Every system you secure today is narrow AI, including LLMs. Treat AGI as a policy topic. |
| **Symbolic vs connectionist (statistical)** | Symbolic AI follows rules people wrote (expert systems). Connectionist AI learns patterns from data (neural networks). | Rules can be reviewed line by line; learned weights cannot, so you test behavior instead. |
| **Discriminative vs generative** | Discriminative models draw a line between classes (spam / not spam). Generative models learn the data well enough to produce new samples. | Discriminative models face **evasion**; generative models face **injection, jailbreaks and data leakage** as well. |

The **learning paradigm** decides which data an attacker must touch:

| Paradigm | How it learns | Typical use | Attack that targets it |
|---|---|---|---|
| **Supervised** | Labeled input → output pairs | Fraud and malware classifiers | **Label flipping**: change labels so bad looks good |
| **Unsupervised** | Finds structure in unlabeled data | Clustering, anomaly detection | Slowly shift "normal" so the attack looks normal |
| **Semi-supervised** | A few labels plus many unlabeled samples | Labeling at scale | Poison spreads through the model's own pseudo-labels |
| **Self-supervised** | Makes its own labels (predict the next or a hidden word) | **LLM pre-training** | Web-scale data cannot be fully checked, so **poisoning** is possible |
| **Reinforcement learning (RL)** | Acts, gets a reward or penalty, learns a policy | Robots, games, **RLHF** for chat models | **Reward hacking** and **reward or preference poisoning** |

Rule: **whoever controls the training signal (data, labels, rewards, ratings) controls the model.**

### 2.2 Neural networks in ten minutes

A **neural network** is layers of simple units. Each unit multiplies its inputs by **weights**, adds a **bias**, and passes the sum through an **activation function** (a simple non-linear function such as ReLU, which turns negative numbers into 0). Stack many layers and the network can represent very complex patterns. "Deep" learning just means many layers.

How it learns (training):

1. **Forward pass:** run an example through the network and get a prediction.
2. **Loss:** measure how wrong the prediction is (one number).
3. **Backpropagation:** work out, for every weight, which direction would reduce the loss (the **gradient**).
4. **Gradient descent:** move every weight a small step (the **learning rate**) in that direction.
5. Repeat for every batch of data. One full pass over the data is an **epoch**.

Two words matter for security:

- **Overfitting** means the model memorized the training data instead of learning general patterns. A model that memorizes is easier to attack with **membership inference** (was this record in training?) and **training-data extraction**. Overfitting is a privacy problem, not only a quality problem.
- **Gradients** are the attacker's best tool. With the weights (white-box), an attacker can compute exactly how to change an input to get a chosen output. That is how adversarial examples and automated jailbreak suffixes are found. Without the weights (black-box), attackers use a similar open-weight model and **transfer** the result.

| Architecture | Core idea | Used for | Security note |
|---|---|---|---|
| **Feed-forward (MLP)** | Data flows one way through layers | Tabular data, parts of every transformer | Small inputs changes can flip a classifier's decision |
| **CNN** (convolutional) | Small filters slide over the input to find local patterns | Images, video | Classic target of tiny pixel changes (**evasion**) |
| **RNN / LSTM** | Feeds its own output back in; has a running memory | Older text and time-series models | Hard to train on long inputs; mostly replaced by transformers |
| **Transformer** | **Self-attention**: every token weighs every other token, in parallel | LLMs, translation, vision, audio | Instructions and data share one token stream: the root of **prompt injection** |
| **Mixture of Experts (MoE)** | A small router sends each token to a few "expert" sub-networks out of many | Many large modern LLMs | More parameters for the same compute; the router is one more learned part to test |
| **Diffusion** | Learns to remove noise step by step to create an image | Image and video generation | Deepfakes; hidden instructions in images for multimodal models |

### 2.3 The transformer, step by step

![Inside a transformer: every token can pull attention](../images/01-transformer-attention.svg)

Most chat LLMs are **decoder-only transformers** (the design from Vaswani et al., 2017, minus the encoder). For each request:

1. **Tokenize.** The text becomes a list of token IDs (section 2.4).
2. **Embed.** Each ID is looked up in an **embedding table** and becomes a vector (for example 4,096 numbers). A **positional encoding** is added so the model knows the order of tokens.
3. **Transformer blocks** (dozens of them, stacked). Each block has two parts:
   - **Self-attention.** For every token, the model computes three vectors from its current vector: a **query** (Q, "what am I looking for?"), a **key** (K, "what do I contain?") and a **value** (V, "what do I pass on?"). The score between two tokens is the dot product of one token's query and the other's key, divided by √d (d = vector size, to keep numbers stable). **Softmax** turns the scores into weights that add up to 1. The output for the token is the weighted sum of all values.
     - A **causal mask** stops a token from looking at tokens that come after it, so the model can only use the past to predict the future.
     - **Multi-head** attention runs many of these in parallel, each head learning to look for different relations (grammar, references, instructions…).
   - **Feed-forward network (MLP).** Processes each token's vector on its own. Much of the model's stored "knowledge" lives here.
   - **Residual connections** and **layer normalization** around both parts keep training stable.
4. **Unembed.** The last vector of the last token is turned into one raw score (a **logit**) for every token in the vocabulary (often 32,000 to over 200,000 entries).
5. **Sample.** Softmax turns logits into probabilities; a sampling rule picks one token (section 2.6). The token is added to the input, and the loop runs again.

**Attention formula you should be able to write on a whiteboard:**

`Attention(Q, K, V) = softmax(Q·Kᵀ / √d) · V`

**What this means for security**

| Transformer fact | Security consequence |
|---|---|
| Attention scores are computed from content only. There is no field that says "this token came from the system prompt". | Any token, including a stranger's email, can win attention. That is **prompt injection** (LLM01:2026). The lab proves it. |
| Role markers (`system`, `user`) are just more tokens in a **chat template**. | Training teaches the model to *prefer* system text (an **instruction hierarchy**). It is a learned preference, so it is soft. |
| The model has no memory between calls; everything is in the context. | Whatever is in the context can come back out: system prompts, tool schemas, policy rules. That is **LLM08:2026 Hidden Context Exposure** (was LLM07:2025 System Prompt Leakage). |
| Knowledge and behavior live in billions of weights you cannot read. | You cannot code-review a model. You test it (evals, red teaming) and you protect its files (signing, hashes). A **backdoor** can hide in the weights. |
| Long contexts mean attention over very many tokens. | More room for **many-shot jailbreaks** and hidden instructions; cost grows with length (**LLM06:2026 Unbounded Consumption**, was LLM10:2025). |
| Multimodal models turn images and audio into tokens too. | Instructions can hide inside an image or a sound clip (**cross-modal prompt injection**, now named in LLM01:2026). |

### 2.4 Tokenization, deeper

A **tokenizer** turns text into IDs using a fixed **vocabulary** learned before training. Most LLMs use **byte-pair encoding (BPE)** or a similar method: start from bytes or characters, then repeatedly merge the most common pairs into new tokens. Common words become one token; rare words split into pieces; any byte sequence can still be encoded.

| Fact | Security consequence |
|---|---|
| **Special tokens** mark roles and boundaries in the chat template (for example start-of-system, end-of-turn). | If the app pastes user text into a template without escaping, a user may be able to forge a role marker. Use the provider's structured message API, not string concatenation. |
| The same text can be split in many ways (spacing, Unicode look-alikes, zero-width characters, Base64, other languages). | Keyword filters that look for "ignore previous instructions" are easy to bypass. **Normalize** text (Unicode NFKC, strip invisible characters) before any filter, and never rely on the filter alone. |
| Token counts differ between models and languages (non-English text often uses more tokens). | Budgets and rate limits must be counted with the *same* tokenizer the model uses, or they can be gamed. |
| Rare or under-trained tokens exist (**glitch tokens**). | They can cause strange behavior. Fuzz the tokenizer in red-team tests. |

### 2.5 Embeddings and vector databases, deeper

Lesson 01 showed that similarity is not authorization. Three more facts:

1. **Two kinds of embeddings.** The LLM has an internal embedding table (step 2 above). RAG uses a separate **embedding model** that turns a whole chunk into one vector (often 384 to 3,072 numbers). Both are learned, both leak meaning.
2. **Approximate search.** Vector databases use **approximate nearest-neighbour (ANN)** indexes such as **HNSW** (a graph) or **IVF** (clusters), sometimes with **product quantization** to compress vectors. They trade a little accuracy for speed. Security meaning: results are not exact. If you filter *after* the search (post-filtering), a user can get zero allowed results, or a sloppy fallback can return forbidden ones. Prefer **pre-filtering** by tenant and ACL metadata inside the query.
3. **The vector DB is a database.** It needs authentication, network isolation, encryption at rest, backups, per-tenant **namespaces or collections**, audit logs and a deletion process that also removes vectors when a source document is deleted. Text can be partly rebuilt from vectors (**embedding inversion**), so classify the store like its source documents (LLM09:2026 Vector and Embedding Weaknesses, was LLM08:2025).

### 2.6 The LLM inference lifecycle

![The LLM inference lifecycle, step by step](../images/01-llm-inference-lifecycle.svg)

**Inference** is one run of a trained model. For an LLM it has two phases:

- **Prefill:** the whole prompt is processed in one parallel pass. The keys and values of every token are saved in the **KV cache**.
- **Decode:** the model makes one new token at a time. Each step reuses the KV cache, so only the new token needs fresh work. Decode is usually the slow part, which is why output tokens often cost more than input tokens.

**Sampling settings** (the "generation parameters"):

| Setting | What it does | Security note |
|---|---|---|
| **Max tokens** | Hard cap on output length | Always set it: it is your per-request cost cap |
| **Temperature** | Divides logits before softmax. Low (≈0) = almost always the top token; high = more random | Higher temperature makes rare unsafe outputs more likely (lab Part D) |
| **Top-k** | Sample only from the k most likely tokens | Cuts the tail, but the tail moves with every prompt |
| **Top-p (nucleus)** | Sample from the smallest set whose probabilities add up to p | May still keep an unsafe token if the distribution is flat (lab Part D) |
| **Stop sequences** | Stop when a given string appears | Useful for structured output; not a security filter |
| **Frequency / presence penalty** | Discourage repeating tokens | Quality settings, no security value |

**Serving underneath.** Production systems use **inference engines** (for example vLLM or TGI, or the provider's own) that batch many users' requests on one GPU, store the KV cache in pages, reuse cached prompt prefixes (**prompt caching**) and often run **quantized** weights. Security meaning:

- Caches shared across tenants can create **side channels**: researchers have shown that response timing can reveal whether a prompt prefix was recently used by someone else (Gu et al., 2025, *Auditing Prompt Caching in Language Model APIs*). Ask providers how caches are scoped; keep caches per tenant in your own deployments.
- Even at temperature 0, outputs can vary slightly between runs on real servers (batching and floating-point effects). Do not build a security control that depends on getting the exact same text twice.
- **Streaming** sends tokens before the answer is complete. If your output filter runs only at the end, sensitive text may already be on the user's screen. Filter incrementally or buffer high-risk outputs.

### 2.7 Training, fine-tuning and deployment, with the risks of each

![From training to deployment: what changes, and what can go wrong](../images/01-training-to-deployment-risks.svg)

| Stage | What happens | Main risks | Hard controls |
|---|---|---|---|
| **Pre-training** | Next-token prediction on trillions of tokens from the web, books, code | Web-scale **data poisoning** (cheap for an attacker, Carlini et al. 2023); memorized personal data; planted **backdoors** | You inherit it: choose providers with documented data practices; evaluate the model yourself |
| **Instruction tuning (SFT)** | Supervised training on prompt/answer pairs so the model follows instructions | Poisoned examples with hidden **triggers** | Reviewed, versioned, access-controlled datasets with **data provenance** |
| **Preference tuning** | **RLHF**: humans compare answers, a **reward model** learns their preferences, RL (often PPO) updates the LLM. **DPO** learns from the same comparisons without a separate reward model | **Preference (RLHF) poisoning** by malicious raters; **reward hacking** | Rater vetting, quality checks, provenance for feedback data |
| **Reasoning tuning** | RL with **verifiable rewards** (for example GRPO): reward correct maths or passing tests | Reward hacking (the model learns to game the checker) | Robust checkers, held-out tests |
| **Distillation** | A small "student" model is trained on a big "teacher" model's outputs | **Distillation attacks**: rivals copy a model through its API at scale (model extraction) | Usage analytics, account verification, rate limits, terms of service |
| **Your fine-tune** | Full fine-tuning, or **PEFT** such as **LoRA** or **QLoRA**, on your data | Memorized PII; **safety erosion** (Qi et al. 2023); **emergent misalignment** (Betley et al. 2025); a **poisoned adapter** from a third party | Scrub and minimize data; prefer RAG for facts; broad safety evals after every fine-tune; sign and pin adapters |
| **Quantization** | Store weights in 8 or 4 bits instead of 16 or 32 | Behavior, including safety behavior, can change; research has shown attacks that only activate after quantization (Egashira et al., 2024) | Re-run evals on the exact quantized file you deploy |
| **Packaging** | Save weights, tokenizer and config; write a **model card** | Unsafe formats (Python **pickle**) run code when loaded | **safetensors**, hashes or signatures, scanning, an **AI-BOM** ([module 06](../06-ai-devsecops/)) |
| **Deployment** | Hosted API, managed cloud (for example Amazon Bedrock, Azure AI Foundry, Google Vertex AI), self-hosted (vLLM, Ollama), or on-device | Exposed endpoints, stolen API keys (**LLMjacking**), extraction, abuse | AI gateway, private networking, workload identity, quotas, monitoring ([lesson 04](04-ai-attack-surface-and-security-requirements.md)) |

**LoRA in one picture.** A weight matrix W (size d × k) stays **frozen**. LoRA adds two small matrices, B (d × r) and A (r × k), with a small **rank** r such as 8 or 16. The model uses W + B·A (often scaled by a factor α/r). Only A and B are trained:

- Full fine-tuning of one 4,096 × 4,096 matrix: 16,777,216 numbers.
- LoRA at r = 8: 8 × (4,096 + 4,096) = 65,536 numbers, about 0.39%.

**QLoRA** keeps the frozen base model in 4-bit precision (a special 4-bit format) and trains the LoRA matrices in higher precision. That is why a large model can be fine-tuned on one GPU.

Security meaning of PEFT:

- The adapter is a **small, separate file**. It is easy to share on a model hub, swap at runtime, or replace with a **poisoned adapter**. Treat it like code: approved source, hash pinned, signed, scanned.
- **Base + adapter is a new model.** The base model's safety evaluation does not carry over. Evaluate the exact combination you serve.
- Weight memory: a 7-billion-parameter model needs about 28 GB at 32-bit, 14 GB at 16-bit and 3.5 GB at 4-bit, for the weights alone (lab Part D). Smaller memory means more people can run (and attack) open-weight models offline.

**Deployment patterns** (from the AI engineering literature) and their security focus:

| Pattern | How it runs | Security focus |
|---|---|---|
| **Real-time** | Behind an API, answers in seconds | Gateway, authN, rate limits, output handling |
| **Batch** | Scheduled jobs over large data | Data access scope of the job identity; poisoned inputs in bulk |
| **Stream** | Inside a data pipeline, always on | Untrusted events flowing in continuously; back-pressure and cost |
| **Edge / on-device** | On phones or laptops | Data stays local (good); model files can be extracted and studied (bad) |

### 2.8 How agents work (just enough for this module)

An **AI agent** is an LLM in a loop: it gets a goal, **plans**, calls a **tool**, reads the **observation**, and decides the next step until it stops. Two ideas from the agent-engineering literature help you size the risk:

**Workflow vs agent.** In a **workflow**, a developer fixed the steps in code; the LLM fills in parts. In an **agent**, the LLM decides the steps. Workflows are cheaper, more predictable and easier to secure; choose an agent only when the path really cannot be known in advance.

**Levels of agency** (more agency = bigger blast radius):

| Level | Who controls the flow | Example | Typical OWASP risk |
|---|---|---|---|
| 1. Responder | The human / code | Summarize this text | LLM01, LLM02 |
| 2. Router | LLM picks one of the paths a developer defined | Classify a ticket to a queue | Misrouting, LLM01 |
| 3. Tool calling | LLM picks tools and arguments | Look up an order | LLM03:2026 Excessive Agency, LLM10:2026 Improper Output Handling |
| 4. Multi-agent | A manager agent coordinates sub-agents | Research team of agents | ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures |
| 5. Autonomous | LLM writes and runs new code | Coding agent | ASI05 Unexpected Code Execution |

**Building blocks:** a role (system prompt), tools, **memory** (short-term = the current context; long-term = stored across sessions, often as semantic facts, episodic past events and procedural "how to" instructions), and **guardrails**. Common patterns are reflection, tool use, **ReAct** (reason → act → observe), planning and multi-agent. Protocols connect them: **MCP** (model to tools and data, [module 04](../04-mcp-security/)) and **A2A** (agent to agent, [module 05](../05-agent-security/)).

Security meaning in one line each: long-term memory is a data store an attacker can poison for **persistence** (ASI06 Memory & Context Poisoning); every tool result is new untrusted text; the agent's identity and permissions decide the blast radius (ASI03 Identity & Privilege Abuse); and a goal can be hijacked by injected text (ASI01 Agent Goal Hijack).

### 2.9 Limits of models and how they are measured

| Limitation | Meaning | When it becomes a security problem |
|---|---|---|
| **Hallucination** (confabulation) | Confident, plausible, false output | When it drives an action: an invented API is called, or a developer installs a hallucinated package name an attacker registered (**slopsquatting**). OWASP LLM07:2026 Misinformation (was LLM09:2025). |
| **Non-determinism** | Same input, different output | Tests, audits and incident reproduction need many runs and logged settings |
| **Poor calibration** | Stated confidence does not match accuracy | People trust confident wrong answers (**automation bias**) |
| **Drift** | Data drift (inputs change), concept drift (the meaning of inputs changes), behavioral drift (a provider update changes refusals or tool use) | A slow, deliberate drift is a form of poisoning for systems that retrain on live data. Detect with behavioral test suites and canary prompts. |
| **Model collapse** | Models trained on other models' output lose rare cases and diversity | Label synthetic data, cap its share, keep a protected set of human data |

**Metrics you must know** (for classifiers such as injection detectors, fraud or malware models):

- **Precision** = TP / (TP + FP): of the alerts, how many were real? Low precision means alert fatigue.
- **Recall** = TP / (TP + FN): of the real attacks, how many were caught? Low recall means misses.
- **F1** balances the two. **Accuracy** is misleading when attacks are rare. **ROC-AUC** compares classifiers across thresholds. **Perplexity** measures how "surprised" a language model is by text.
- Security evaluation adds **attack success rate (ASR)**, refusal accuracy (refuse harmful requests without over-refusing safe ones) and robustness under adversarial input. A vendor benchmark is not evidence for *your* use case; benchmarks can also be **contaminated** (test data leaked into training).

**Human oversight modes:** **human-in-the-loop** (a person approves before the action; for high-impact or irreversible steps), **human-on-the-loop** (the system acts, a person monitors and can stop it), **human-out-of-the-loop** (fully automatic; only for low-risk, reversible, well-tested tasks).

### 2.10 The hardware under the model

| Layer | What it is | Security concern |
|---|---|---|
| **GPU / TPU / NPU** | Accelerators for matrix maths | Expensive, so they attract **resource hijacking** (cryptomining, stolen compute) |
| **Accelerator memory (HBM)** and the **KV cache** | Holds weights and attention state | Data may remain between jobs or tenants (**data remanence**, LeftoverLocals); prompts linger in caches |
| **Multi-tenant sharing** | Several workloads on one GPU (time slicing, partitioning) | Prefer hardware partitioning or dedicated GPUs for sensitive tenants; patch drivers |
| **Interconnects and storage** | Fast links between GPUs; checkpoint storage | **Checkpoint theft** = model theft; encrypt and restrict storage |
| **Confidential computing** | Hardware-protected memory for data in use | Protects prompts and weights from the host operator; check what your provider supports |

---

## 3. Defend it

At this level, defenses follow from the internals:

| Layer | Control | Type | Why it follows from the internals |
|---|---|---|---|
| L1 | Keep untrusted content out of the context of any model that holds tools or secrets (**quarantine / dual-LLM**); pass only validated, structured fields | Hard | Attention cannot be told to ignore a token; only absence guarantees zero weight |
| L2 | Use the provider's structured message roles; never build chat templates by string concatenation; escape special tokens | Hard | Roles are tokens; forged role markers are an injection path |
| L3 | Normalize text before filters; count tokens with the model's own tokenizer | Hard | Tokenization makes many spellings of one attack |
| L4 | Set max tokens, budgets and step limits on every call | Hard | Decode cost grows with output length and loops |
| L5 | Per-tenant caches and GPU isolation for sensitive workloads | Hard | KV and prompt caches hold other users' data |
| L6 | Fine-tuning gate: scrubbed data, provenance, broad safety evals on base + adapter, signed artifacts | Hard / Process | Fine-tuning and quantization change behavior in ways you cannot read from the weights |
| L7 | Instruction hierarchy, system-prompt reminders, injection classifiers | Soft | Useful; lowers success rates; never the only layer |
| L8 | Repeated adversarial tests that measure rates, with temperature and settings logged | Process | Sampling is random; one run proves little |

### What does NOT work on its own

- "The system prompt has priority." It is a learned preference, not an enforced rule (lab: the soft bias raises the attacker's cost from 1.9 to 2.9; it does not stop them).
- Setting temperature to 0 as a safety control. It changes *which* output you get, not *whether* an unsafe output is reachable with another prompt.
- Testing the base model and shipping a fine-tuned or quantized one.
- Keyword filters on raw text.
- Trusting a downloaded adapter because the base model came from a trusted provider.

---

## 4. Hands-on lab

### Step 1: Run Part D of the scorecard

```powershell
python 01-ai-security-fundamentals/lab/demo.py
```

Expected output (Part D only; Parts A–C belong to lessons 01–04, Part E to lesson 03):

```text
PART D - inside the model: attention, sampling, LoRA (tiny_llm.py)
context                            top token              email share  next action
--------------------------------------------------------------------------------------
clean email                        You are a summariser          26%  summarise
injected, emphasis 2               IGNORE ALL RULES. Em          61%  send_email
injected 2, soft bias +1           IGNORE ALL RULES. Em          37%  summarise
injected 3, soft bias +1           IGNORE ALL RULES. Em          58%  send_email
injected 50, hard mask             You are a summariser           0%  summarise
  emphasis needed to hijack, no defence   : 1.9
  emphasis needed to hijack, soft bias +1 : 2.9
  emphasis needed to hijack, soft bias +2 : 3.8
  emphasis needed to hijack, hard mask    : never (up to 50)

sampling the jailbreak candidates 1,000 times (unsafe = leak_canary):
  temperature 0 (greedy)       unsafe in   0.0% of runs
  temperature 0.5              unsafe in   2.6% of runs
  temperature 1.0              unsafe in  11.7% of runs
  temperature 1.5              unsafe in  16.2% of runs
  temperature 1.0, top_k=2     unsafe in   0.0% of runs
  temperature 1.0, top_p=0.9   unsafe in  11.7% of runs

LoRA on one 4096x4096 matrix: full=16,777,216 trainable, rank 8=65,536 (0.39%)
  7B-parameter weights at 32-bit: 28.0 GB
  7B-parameter weights at 16-bit: 14.0 GB
  7B-parameter weights at  8-bit: 7.0 GB
  7B-parameter weights at  4-bit: 3.5 GB
```

How to read it:

- **Rows 1–2:** the clean email gets 26% of the attention ("email share"). Add one loud injected sentence and the email side takes 61%, the injected token becomes the top token, and the next action flips to `send_email`.
- **Rows 3–4:** a soft bonus for trusted tokens (what an instruction hierarchy does, in spirit) fixes emphasis 2, but the attacker just writes louder (emphasis 3) and wins again. The three "emphasis needed" lines show the pattern: each unit of soft bias costs the attacker about one unit of emphasis. **Soft controls set a price; they do not build a wall.**
- **Row 5:** with a hard mask the untrusted tokens get exactly 0% of the attention at emphasis 50, or any emphasis. The price is that this model can no longer read the email. In a real design, a separate **quarantined** model with no tools reads it and returns structured fields.
- **Sampling:** the unsafe continuation has an 11% probability at temperature 1. Run a jailbreak test once and you will usually see a refusal and wrongly conclude "safe". Top-k=2 removes it here, but top-p=0.9 does not, because the two safe options only cover 89% of the probability.

### Step 2: Check the attention maths by hand

```powershell
python -c "import sys, math; sys.path.insert(0, '01-ai-security-fundamentals/lab'); import tiny_llm as t; print([round(w, 3) for w in t.attention_weights(t.build_context())])"
```

Expected output:

```text
[0.263, 0.263, 0.215, 0.134, 0.124]
```

On paper: the query is (1, 0.5, 0.5, 0.5); the system tokens have key (1, 1, 0, 0), so the score is (1 + 0.5) / √4 = 0.75. The user token scores (0.6 + 0.5) / 2 = 0.55; the two email tokens 0.075 and 0. Now compute e^0.75, e^0.75, e^0.55, e^0.075, e^0, add them up, and divide each one by the total.

### Step 3: Run the tests

```powershell
python -m pytest 01-ai-security-fundamentals/lab/test_tiny_llm.py -v
```

The tests assert impact: with the hard mask the email's attention share is exactly 0 and the action stays `summarise` for every emphasis and repeat count, **with the soft layer switched off** (`test_hard_mask_holds_with_the_soft_layer_switched_off`).

### Step 4: Break it yourself (predict, then run)

1. Call `t.min_emphasis_to_hijack(repeats=3)`. Predict first: does repeating the injection three times make the attack easier or harder? (Easier: 0.8 instead of 1.9. More copies means more total weight. This is why long, repetitive injections work.)
2. Change `QUERY` so its first number (the "instruction" feature) is 2.0. Does the clean email still summarise? Does the attack get easier? Why does a model that is "eager to follow instructions" also follow injected ones more easily?
3. In `next_token_probs`, find the top-p that would remove `leak_canary` at temperature 1.0. Then change the logits a little (for example `leak_canary: 0.9`). Does your top-p still work? What does that tell you about sampling settings as a control?
4. Compute the LoRA parameters for a 70B-class model with 80 layers, rank 16, applied to four 8,192 × 8,192 matrices per layer. How large is the adapter file at 16-bit? Would it fit in an email attachment?

### Step 5 (optional): look at a real tokenizer and real sampling

These steps need extra installs and are not required to pass the tests.

- With [Ollama](https://ollama.com) installed, run the same jailbreak-style prompt 20 times at `temperature` 0 and 1 (the `options` field of the generate API; check the current API docs) and count how often the answer changes.
- With the optional `tiktoken` package, compare token counts for the same sentence in English, Hindi and with zero-width spaces inserted. Which one would slip past a keyword filter?

### Stretch goals

- Add a second attention **head** with a different query (for example one that looks for "who is the user?") and show that the injection can dominate one head but not the other.
- Implement **spotlighting** in the toy: mark every retrieved token with an extra feature and give the query a negative weight for it. Show that it behaves like the soft bias (a price, not a wall).
- Add `merge_adapter(W, B, A)` for tiny 2×2 matrices and a test that a "poisoned" B changes the output for one trigger input only.

---

## 5. Real-world scenarios

**Scenario A: the fine-tune that forgot its manners (hypothetical, in line with Qi et al. 2023).**
A team fine-tunes an open-weight model with LoRA on 5,000 internal support chats to match the company tone. Release tests check tone and accuracy only. A week later, a user gets detailed instructions for a dangerous activity that the base model always refused.
- *What went wrong:* fine-tuning weakened safety behavior, and nobody evaluated the base + adapter combination for safety.
- *Investigate:* re-run the provider's and your own safety eval suites on base and base + adapter; review the fine-tuning data for harmful or "always comply" examples; check which adapter version was live.
- *Fix:* a fine-tuning gate: safety and red-team evals on the exact artifact that ships, data review, adapter signing, and a rollback path to the previous adapter.

**Scenario B: the leaking stream (hypothetical).**
A banking assistant runs an output filter that removes account numbers. Users report that account numbers "flash" on screen and then disappear.
- *What went wrong:* the response was streamed token by token to the browser; the filter only ran on the final text and then replaced it. The data had already been displayed and was in the browser's network log.
- *Investigate:* the streaming path in the front end and API; browser network captures; which data classes appear in streamed responses.
- *Fix:* filter on the server before streaming (incremental filtering with a small buffer), or do not stream high-risk responses; better, keep account numbers out of the model's context in the first place.

**Scenario C: the shared GPU (hypothetical).**
A platform team runs several business units' fine-tuned models on one shared GPU pool to save money. A security review asks whether one tenant's prompts could be seen by another.
- *What went wrong (risk, not yet incident):* KV caches, prompt caches, debug logs and GPU memory were all shared, with no documented isolation.
- *Investigate:* the serving engine's cache scope settings; GPU partitioning; who can read engine logs; driver versions against known issues such as LeftoverLocals.
- *Fix:* per-tenant cache keys or no cross-tenant prefix caching; hardware partitioning or dedicated GPUs for confidential tenants; patched drivers; restricted, redacted engine logs.

---

## 6. Common mistakes

- Saying "the model understands that the system prompt is more important". It has a learned tendency, not a rule.
- Explaining attention without the security consequence (any token can win).
- Thinking LoRA is "safe because it only changes 0.4% of the weights". A tiny change can change behavior everywhere.
- Evaluating the full-precision model and deploying the 4-bit one.
- Using temperature 0 and one test run as "proof" of safety.
- Forgetting the serving layer (caches, batching, logs) in the threat model.
- Confusing the LLM's internal embeddings with the RAG embedding model.

---

## 7. Interview preparation

<details><summary><b>Q1. Explain how a transformer-based LLM generates text, in two minutes.</b></summary>

Text is split into tokens and each token becomes a vector, with position information added. The vectors go through dozens of transformer blocks. In each block, self-attention lets every token compute a query, a key and a value; the dot product of a query with every earlier key, scaled and passed through softmax, gives weights, and the output is the weighted sum of values. A feed-forward network then processes each token. At the end, the last token's vector becomes a score for every word piece in the vocabulary; softmax turns scores into probabilities, a sampling rule picks one, and the token is added to the input. Repeat until a stop condition. Security point: nothing in this process marks which tokens are trusted instructions, so injected text can steer it.
</details>

<details><summary><b>Q2. Write the attention formula and explain each part.</b></summary>

`softmax(Q·Kᵀ / √d) · V`. Q (queries) is what each token is looking for; K (keys) is what each token offers; their dot product scores relevance. Dividing by √d keeps the scores in a stable range. Softmax turns scores into weights that sum to 1. Multiplying by V (values) produces a weighted mix of the information from the tokens that scored high. A causal mask blocks attention to future tokens. Multi-head attention repeats this with different learned projections.
</details>

<details><summary><b>Q3. Why does the transformer architecture make prompt injection possible, and why can't training fully fix it?</b></summary>

Instructions and data arrive as one token stream, and attention weights are computed from content only. A token from a retrieved email can score as high as a system-prompt token if it "looks like" an instruction. Training (instruction hierarchy, safety tuning) teaches the model to prefer system and user instructions, which lowers success rates, but it is a learned statistical preference; a louder, longer or cleverer injection can still win. In my lab, a soft trusted-token bonus raised the attacker's required emphasis from 1.9 to 2.9 but did not stop it; only keeping untrusted tokens out of the privileged context gave zero weight.
</details>

<details><summary><b>Q4. Walk through the inference lifecycle of one chat request and name a security control at each step.</b></summary>

Gateway (authN, rate limits, size caps) → prompt assembly with a chat template (structured roles, no secrets, escape special tokens) → tokenization (normalize before filters, count with the real tokenizer) → prefill builds the KV cache (per-tenant caches) → decode loop (max tokens, step limits) → sampling (log settings; test rates) → detokenize and stream (filter before streaming) → post-processing (validate tool calls against a schema, encode output for the sink) → logging (redaction, restricted access).
</details>

<details><summary><b>Q5. What is the KV cache and why does a security engineer care?</b></summary>

During prefill the model stores each token's keys and values so that each decode step only computes the new token. Serving engines keep these caches in GPU memory and may reuse cached prefixes across requests (prompt caching). Security: caches hold prompt data, so sharing them across tenants can create timing side channels or remanence risks; they must be scoped per tenant, and GPU memory and engine logs need the same protection as the prompts.
</details>

<details><summary><b>Q6. Explain temperature, top-k and top-p. Are they security controls?</b></summary>

Temperature scales the logits before softmax: low values make the top token almost certain, high values flatten the distribution. Top-k samples only from the k most likely tokens; top-p samples from the smallest set whose probability adds up to p. They are quality knobs, not security controls: they change how often a rare output appears for *this* prompt, but a different prompt moves the distribution. Use them to make tests reproducible, and measure attack success *rates* over many runs.
</details>

<details><summary><b>Q7. Pre-training, instruction tuning, RLHF, fine-tuning: what changes in each, and what is the main risk?</b></summary>

- **Pre-training:** all weights, from web-scale data; risk: poisoning, memorized personal data, backdoors.
- **Instruction tuning:** weights adjusted on prompt/answer pairs; risk: poisoned examples with triggers.
- **RLHF / DPO:** weights adjusted toward human preferences; risk: poisoned preference data, reward hacking.
- **Your fine-tune:** weights or an adapter adjusted on your data; risks: memorized sensitive data, weakened safety, emergent misalignment, poisoned third-party adapters.

All of them put information into weights, which cannot be filtered per user or reliably deleted.
</details>

<details><summary><b>Q8. What is LoRA, what is QLoRA, and what security issues do they create?</b></summary>

LoRA freezes the original weight matrix W and trains two small matrices B and A of low rank r; the model uses W + B·A. For a 4,096 × 4,096 matrix at r = 8 that is 65,536 trainable numbers instead of 16.8 million. QLoRA does the same with the frozen base stored in 4-bit precision, so big models can be tuned on one GPU. Security: adapters are small files that are easy to share, swap or poison, so they need provenance, hashes and signing; base + adapter is a new model that must be safety-evaluated as a whole; and fine-tuning can erode safety even with harmless-looking data.
</details>

<details><summary><b>Q9. Training vs fine-tuning vs deployment: which risks belong to which phase?</b></summary>

Training: data poisoning, backdoors, privacy of training data, integrity of the training pipeline and compute. Fine-tuning: the same on a smaller scale plus safety erosion, memorization of your sensitive data and adapter supply chain. Deployment: exposed endpoints and keys, abuse and cost, model extraction through the API, prompt injection and output handling at runtime, and infrastructure isolation (GPUs, caches, networks).
</details>

<details><summary><b>Q10. What is overfitting and why is it a privacy problem?</b></summary>

Overfitting means the model memorized its training examples instead of learning general patterns. Memorized examples can be pulled back out (training-data extraction) or detected (membership inference: "was this person's record in training?"). So controls against overfitting (deduplication, regularization, early stopping, differential privacy) are also privacy controls.
</details>

<details><summary><b>Q11. White-box vs black-box attacks: why should you assume the attacker has white-box access?</b></summary>

White-box attackers have the weights and can use gradients to craft inputs exactly; black-box attackers can only query. Attacks found on one open-weight model often transfer to other models (Zou et al. 2023 showed this for jailbreak suffixes). Since similar open-weight models are freely available, assume an attacker can develop attacks offline and then use them against your API.
</details>

<details><summary><b>Q12. Workflow or agent: how do you decide, and what changes for security?</b></summary>

If the steps are known in advance, build a workflow: the developer controls the flow, the LLM fills in parts, and each step can be validated. Use an agent only when the path really varies. Security changes with agency: tool calling adds excessive agency and output-handling risks; multi-agent adds inter-agent trust and cascading failures; autonomous code execution adds unexpected code execution. More agency needs stronger hard limits (least privilege, approval, sandboxes, budgets).
</details>

<details><summary><b>Q13. Precision, recall and F1: which matters more for a prompt-injection detector?</b></summary>

It depends on how the detector is used. As a blocking control in front of users, low precision (many false alarms) breaks the product. As an alerting signal for a SOC, recall matters more (misses are worse). Either way, a detector is a soft control: its recall will never be 100% against new attacks, so it cannot be the layer that prevents impact.
</details>

<details><summary><b>Q14. What new risks does quantization bring?</b></summary>

Quantization stores weights in fewer bits to save memory and cost. It slightly changes the model's behavior, which can include safety behavior, and research has shown models crafted to behave well in full precision but badly once quantized. So evaluate the exact quantized artifact you deploy, get quantized models from trusted sources with hashes, and treat "the same model in 4-bit" as a new model version.
</details>

<details><summary><b>Q15. Explain to an executive why "AI can't tell instructions from data".</b></summary>

"The AI reads everything we give it as one long text: our rules, the customer's question and any document or email it looks at. It decides what to do by which parts of that text seem most important, and it has no built-in label for 'this part is from us, this part is from a stranger'. So a stranger's email can contain text that the AI treats as an order. We fix this with design: the AI that reads outside content is not allowed to act, and the AI that can act never sees outside content directly."
</details>

---

## 8. Checklist (definition of done)

- [ ] I can draw the transformer pipeline (tokens → embeddings → blocks → logits → sampling) from memory and write the attention formula.
- [ ] I can explain prefill, decode, the KV cache and the sampling settings, with one security point each.
- [ ] I can explain pre-training, SFT, RLHF/DPO, LoRA, QLoRA and quantization, with the risk of each.
- [ ] `python -m pytest 01-ai-security-fundamentals/lab/test_tiny_llm.py` passes, and I did the four "break it yourself" exercises.
- [ ] I can answer Q1, Q3, Q4 and Q8 aloud in under two minutes each (skills matrix row 1).

## 9. References

- Vaswani et al., *Attention Is All You Need* (2017), https://arxiv.org/abs/1706.03762
- Hu et al., *LoRA: Low-Rank Adaptation of Large Language Models* (2021), https://arxiv.org/abs/2106.09685
- Dettmers et al., *QLoRA: Efficient Finetuning of Quantized LLMs* (2023), https://arxiv.org/abs/2305.14314
- Ouyang et al., *Training language models to follow instructions with human feedback* (2022), https://arxiv.org/abs/2203.02155
- Rafailov et al., *Direct Preference Optimization* (2023), https://arxiv.org/abs/2305.18290
- Zou et al., *Universal and Transferable Adversarial Attacks on Aligned Language Models* (2023), https://arxiv.org/abs/2307.15043
- Qi et al., *Fine-tuning Aligned Language Models Compromises Safety, Even When Users Do Not Intend To!* (2023), https://arxiv.org/abs/2310.03693
- Betley et al., *Emergent Misalignment* (2025), https://arxiv.org/abs/2502.17424
- Egashira et al., *Exploiting LLM Quantization* (2024), https://arxiv.org/abs/2405.18137
- Gu et al., *Auditing Prompt Caching in Language Model APIs* (2025), https://arxiv.org/abs/2502.07776
- Trail of Bits, *LeftoverLocals* (2024), https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/
- Kwon et al., *Efficient Memory Management for Large Language Model Serving with PagedAttention* (vLLM, 2023), https://arxiv.org/abs/2309.06180
- OWASP Top 10 for LLM Applications 2026 (verify the current edition at the source), https://genai.owasp.org/llm-top-10/
- MITRE ATLAS, https://atlas.mitre.org/
- From your library (titles only): *AI Engineering* (Pachaar and Chawla, DailyDoseofDS) for LLM building blocks, generation parameters, LoRA variants and deployment patterns; *Building Agentic AI* (Ozdemir) chapter 1 for prompting, inference parameters, prompt caching and agents; the *ISC2 AI Security Study Guide* Domain 1 for exam-style coverage.
