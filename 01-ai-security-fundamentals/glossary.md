# AI Security Glossary

> **Module:** 01 · AI Security Fundamentals · use it in every module of this repo.
> About 160 terms, grouped so that each section only needs terms from the sections before it. Every entry has a plain meaning and the reason a security engineer cares. Written in our own words for this repo. Where an entry has an OWASP id, it uses the **2026** list, with the **2025** id in brackets.

**How to use it:** read sections 1–3 in week 1, the rest as you meet the terms. Before an interview, cover the "Why security cares" column and explain each term aloud. Related lessons: [01](01-ai-ml-llm-basics-for-security.md), [01b](01b-inside-the-llm-transformers-inference-and-training.md), [02](02-ai-system-architecture-and-trust-boundaries.md), [03](03-ai-threat-modeling.md), [04](04-ai-attack-surface-and-security-requirements.md).

**Sections:** [1 Foundations](#1-ai-and-model-foundations) · [2 How LLMs work](#2-how-llms-work-inside) · [3 How AI apps are built](#3-how-ai-applications-are-built) · [4 Security concepts](#4-security-concepts-applied-to-ai) · [5 Prompt and input attacks](#5-prompt-and-input-attacks) · [6 Data and training attacks](#6-data-and-training-attacks) · [7 Model theft and privacy](#7-model-theft-and-privacy-attacks) · [8 Supply chain](#8-ai-supply-chain) · [9 Agentic risks](#9-agentic-ai-and-mcp-risks) · [10 AI-enabled attacks](#10-attacks-that-use-ai) · [11 Defences](#11-defences-and-controls) · [12 Governance](#12-governance-risk-and-frameworks)

---

## 1. AI and model foundations

| Term | Meaning | Why security cares |
|---|---|---|
| **Artificial intelligence (AI)** | Software that does tasks we link with human judgement: recognizing, predicting, writing. Today it usually means systems that learn from data. | The word is too broad for a policy or audit. First agree which systems, data and actions you mean. |
| **Narrow AI / general AI (AGI)** | Narrow AI does specific tasks; AGI would match humans at everything and does not exist yet. | Everything you secure today, LLMs included, is narrow AI. |
| **Machine learning (ML)** | AI that learns patterns from examples instead of following written rules. | Behavior comes from data, so data becomes an attack target. |
| **Deep learning** | ML with neural networks of many layers. | Very capable, but the result cannot be read like code; you must test behavior. |
| **Supervised / unsupervised / self-supervised learning** | Learning from labeled pairs / from structure in unlabeled data / from labels the data provides itself (such as the next word). | Each has its own poisoning route: labels, "normal" clusters, or web-scale text. |
| **Reinforcement learning (RL)** | Learning a policy by trying actions and receiving rewards or penalties. | Whoever controls the reward controls the learned behavior (**reward hacking**, reward poisoning). |
| **Training data** | The examples a model learns from. | May contain personal data, secrets or copyrighted text that can come back out; also a poisoning target. |
| **Model** | The learned numbers plus the code structure that turns input into output. | A high-value asset that can be stolen, swapped or tampered with. |
| **Parameters (weights)** | The learned numbers inside a model; large models have billions. | The weights *are* the model: leaked weights give away the full capability; small edits can hide a backdoor. |
| **Training** | The compute-heavy process of adjusting weights to fit the data. | The training pipeline needs the same integrity controls as a software build. |
| **Inference** | Using a trained model to produce an output. | Where most attacks happen in production, and where costs build up. |
| **Discriminative vs generative model** | One separates classes; the other produces new content. | Generative models add injection, leakage and harmful-content risks. |
| **Generative AI (GenAI)** | AI that produces text, images, audio, video or code. | Output can be wrong, harmful, leaked or fake, and it flows into documents, code and decisions. |
| **Foundation model** | A large general model that many products adapt. | Concentration risk: one provider's flaw or outage reaches every product built on it. |
| **Large language model (LLM)** | A foundation model trained on huge amounts of text to predict the next token. | It has no built-in separation between instructions and data. |
| **Small language model (SLM)** | A smaller LLM that can run on modest hardware or devices. | Easier to self-host (data stays inside), but patching and testing become your job. |
| **Multimodal model** | A model that takes or produces several types of data (text, image, audio). | Every new input type is a new injection channel. |
| **Open-weight model** | A model whose weights can be downloaded and run by anyone. Not the same as open source (training data and code may be closed). | You control the data path, but attackers can study the same weights offline. |
| **Reasoning model** | An LLM trained to work step by step before answering. | Its reasoning traces can leak data (named in LLM02:2026) and are valuable enough that rivals try to copy them. |
| **Alignment / safety training** | Extra training that makes a model helpful and refuse harmful requests. | It lowers risk but can be bypassed (jailbreaks) or weakened by fine-tuning. |
| **Hallucination (confabulation)** | Confident, plausible, false output. | Becomes a security issue when it drives actions or installs (see **slopsquatting**). |
| **Non-determinism** | The same input can give different outputs. | One test run proves little; measure rates and log settings. |
| **Drift** | Inputs, their meaning or the model's behavior change over time. | Slow, deliberate drift is a form of poisoning; behavioral drift follows provider updates. |
| **Model collapse** | Quality loss when models are trained on other models' output. | Label and limit synthetic data; keep verified human data. |

## 2. How LLMs work inside

| Term | Meaning | Why security cares |
|---|---|---|
| **Neural network** | Layers of units that multiply inputs by weights, add a bias and apply an activation function. | Behavior is spread over millions of numbers that cannot be reviewed. |
| **Activation function** | A simple non-linear function (for example ReLU) inside each unit. | Background knowledge for interviews; no direct control. |
| **Backpropagation / gradient descent** | How training finds and applies the weight changes that reduce the error. | Gradients let white-box attackers craft adversarial inputs precisely. |
| **Overfitting** | The model memorizes training examples instead of general patterns. | Raises the risk of training-data extraction and membership inference. |
| **Transformer** | The neural network design behind modern LLMs, built on self-attention. | Instructions and data share one token stream: the root of prompt injection. |
| **Self-attention** | Each token computes query, key and value vectors; softmax(Q·K/√d) decides how much it uses every other token. | Weights depend on content only, so an injected token can dominate (lab: `tiny_llm.py`). |
| **Multi-head attention** | Several attention computations in parallel, each learning different relations. | Interview vocabulary; more heads do not add a trust boundary. |
| **Causal mask** | Stops a token from attending to later tokens. | Explains why order in the prompt matters, not a security control. |
| **Positional encoding** | Information about each token's position added to its vector. | Background for long-context behavior. |
| **Mixture of Experts (MoE)** | A router sends each token to a few of many expert sub-networks. | More capacity for the same compute; one more learned component to evaluate. |
| **Token** | The unit an LLM reads and writes: a word, a word piece or a byte sequence. | Cost, limits and context are measured in tokens; tokenization quirks bypass filters. |
| **Tokenizer / BPE** | The component that maps text to token IDs; byte-pair encoding is the common method. | Many spellings of the same attack exist; normalize before filtering. |
| **Special tokens / chat template** | Reserved tokens and the format that mark system, user and assistant turns. | Roles are just tokens; string-built templates can let users forge them. |
| **Glitch token** | A rare or under-trained token that triggers odd behavior. | A fuzzing target in red teams. |
| **Embedding** | A vector of numbers that represents meaning. | Not anonymous: text can be partly rebuilt from it. |
| **Context window** | The maximum number of tokens (input plus output) a model handles at once. | Overflow handling can push out safety instructions; long contexts enable many-shot attacks. |
| **Logits** | The raw score the model gives each possible next token. | Exposed logits or probabilities help extraction and membership attacks. |
| **Softmax** | The function that turns scores into probabilities that add up to 1. | Background for attention and sampling. |
| **Temperature, top-k, top-p** | Sampling settings that control randomness. | Change how often rare unsafe outputs appear; not security controls. |
| **Prefill and decode** | Processing the whole prompt in one pass; then generating one token at a time. | Output length drives cost; cap it. |
| **KV cache** | Stored keys and values from earlier tokens, reused during decoding. | Holds prompt data in GPU memory; scope caches per tenant. |
| **Prompt caching** | Reusing the computation for a repeated prompt prefix. | Shared caches can create timing side channels across users. |
| **Inference engine** | Server software that runs models efficiently (for example vLLM, TGI). | Its batching, caches and logs are part of the attack surface. |
| **Pre-training** | The first, huge training run on next-token prediction. | Web-scale data cannot be fully vetted. |
| **Instruction tuning (SFT)** | Supervised training on prompt/answer pairs. | Poisoned examples can plant triggers. |
| **RLHF / DPO** | Training on human preference comparisons (with a reward model and RL, or directly). | Preference data can be poisoned. |
| **Fine-tuning** | Further training of an existing model on your data. | Can memorize your sensitive data and weaken safety behavior. |
| **PEFT** | Parameter-efficient fine-tuning: train a few added or chosen parameters. | Produces small, swappable artifacts that need supply-chain controls. |
| **LoRA** | Low-rank adaptation: freeze W, train small matrices B and A, use W + B·A. | Tiny adapter files are easy to share, swap and poison. |
| **QLoRA** | LoRA on a base model stored in 4-bit precision. | Brings fine-tuning to one GPU, so more people (and attackers) can do it. |
| **Quantization** | Storing weights with fewer bits (8, 4). | Behavior can change; evaluate the exact quantized file. |
| **Distillation** | Training a small model on a big model's outputs. | Done without permission it becomes a **distillation attack**. |
| **Precision / recall / F1** | Share of alerts that are real / share of real cases caught / their balance. | How you judge detectors and classifiers; accuracy misleads when attacks are rare. |
| **Perplexity** | How surprised a language model is by a text (lower is better). | Used in some detectors of odd, machine-crafted prompts. |
| **Benchmark contamination** | Test questions leaked into training data. | A vendor score may not reflect real ability or safety. |

## 3. How AI applications are built

| Term | Meaning | Why security cares |
|---|---|---|
| **AI system** | The whole product around the model: data, retrieval, tools, UI, identities, logs and people. | Most failures are in the system, not the model. |
| **Prompt** | The input to an LLM: instructions, questions, documents. | Whoever can write into the prompt can influence the output. |
| **System prompt** | Developer instructions placed before user input. | Not secret and not a boundary: LLM08:2026 Hidden Context Exposure (was LLM07:2025 System Prompt Leakage). |
| **Hidden context** | Everything in the context the user does not see: system prompt, tool schemas, policy rules, retrieved text. | Can be extracted; never put secrets or access logic there. |
| **Context engineering** | Deciding what goes into the context for each step of a task. | Each source you add is a new trust decision. |
| **Retrieval-augmented generation (RAG)** | Fetching relevant documents at query time and putting them in the context. | Retrieval must enforce permissions; documents can carry injections. |
| **Chunking** | Splitting documents into pieces before embedding. | Chunks must keep their ACL and tenant metadata. |
| **Vector database** | A store that finds the closest embeddings to a query. | Similarity is not authorization; protect it like the source data. |
| **ANN index (HNSW, IVF)** | Approximate nearest-neighbour search structures. | Approximate results make post-filtering unreliable; pre-filter. |
| **Reranking** | A second model reorders retrieved chunks by relevance. | Manipulated relevance can push poisoned content to the top. |
| **AI assistant (copilot)** | A chat or embedded helper inside a product. | Often reads untrusted content while holding the user's access. |
| **Tool (function calling)** | The model outputs a structured request; the application decides whether to run it. | The request is untrusted input to your code. |
| **Connector (plugin)** | A packaged integration that gives an assistant access to a data source or service. | Each connector widens what an injection can reach. |
| **AI agent** | An LLM in a loop that plans, calls tools, observes and acts towards a goal. | Autonomy multiplies blast radius. |
| **Workflow (LLM workflow)** | A fixed sequence written by developers in which the LLM fills in parts. | More predictable and easier to secure than an agent. |
| **ReAct** | A pattern where the model alternates reasoning, acting and observing. | Every observation is new untrusted text. |
| **Agent memory** | Stored information an agent reuses across turns or sessions (short-term, long-term). | A poisoning target that gives attackers persistence. |
| **Multi-agent system** | Several agents that hand work to each other. | Trust between agents must be authenticated and limited. |
| **Model Context Protocol (MCP)** | An open protocol for connecting AI apps (hosts and clients) to tool and data servers. | Servers, tool descriptions and tokens are all attack surface ([module 04](../04-mcp-security/)). |
| **Agent-to-agent protocol (A2A)** | A protocol for agents to discover each other and delegate tasks. | Agent identity and message integrity become critical. |
| **Agentic browser** | A browser with a built-in agent that can click and fill forms as the user. | Reads untrusted pages while holding the user's sessions. |
| **AI coding assistant** | A tool that writes, edits or runs code for developers. | Can introduce vulnerable code (LLM10:2026 covers insecure AI-generated code) and run commands. |
| **AI gateway** | A proxy in front of model APIs for authentication, quotas, logging and filtering. | The natural place for central policy and monitoring. |

## 4. Security concepts, applied to AI

| Term | Meaning | Why security cares |
|---|---|---|
| **AI security vs AI safety** | Security protects AI systems from attackers; safety prevents harm from the system's own behavior. | The two overlap (jailbreaks are both); teams must agree who owns what. |
| **AI attack surface** | Every point where an attacker can put data in, get data out or influence the build. | Includes data, models, tools, infrastructure and people ([lesson 04](04-ai-attack-surface-and-security-requirements.md)). |
| **Trust boundary** | A line where the level of trust changes. | Data crossing it needs an enforced check ([lesson 02](02-ai-system-architecture-and-trust-boundaries.md)). |
| **Instruction and data separation** | Keeping commands apart from content. | LLMs cannot do it internally, so the system must. |
| **Taint** | The property of data that came from an untrusted source. | In LLM systems taint does not wash out. |
| **Blast radius** | How much damage one failure can cause. | Least privilege and isolation keep it small. |
| **Least privilege (for AI)** | Give a model, tool or agent only the access the task needs. | The main limit on what a successful injection can do. |
| **Confused deputy** | A privileged component tricked into acting for a less-privileged requester. | Agents with shared service accounts are classic confused deputies. |
| **Human-in-the-loop / on-the-loop** | A person approves before an action / monitors and can stop actions. | Approval works only if the reviewer sees exact details and can say no. |
| **AI threat modeling** | Structured analysis of what can go wrong with an AI system and what to do about it. | The cheapest control ([lesson 03](03-ai-threat-modeling.md)). |
| **White-box / black-box / grey-box** | Attacker knows the weights / can only query / knows something (for example the base model). | Assume white-box access to a similar model; attacks transfer. |
| **Attack success rate (ASR)** | Share of attempts that achieve the attacker's goal. | The right metric for probabilistic attacks. |
| **Shared responsibility model (AI)** | The split of duties between AI provider and customer. | Data, prompts, connectors, access and use of outputs stay with the customer. |
| **Lethal trifecta** | Private data + untrusted content + an exfiltration channel in one model context. | Break one leg with a hard control. |

## 5. Prompt and input attacks

| Term | Meaning | Why security cares |
|---|---|---|
| **Prompt injection** | Text that makes the model follow the attacker's instructions instead of the intended ones. | LLM01:2026 (also LLM01:2025). No complete fix exists; limit impact. |
| **Direct prompt injection** | The user types the attack. | Matters most when the user should not control the system's actions or data. |
| **Indirect prompt injection** | The attack sits in content the model reads: email, web page, document, tool result. | The victim does nothing wrong; the attacker never logs in. |
| **Zero-click prompt injection** | Indirect injection that triggers when an assistant processes content automatically. | No user action needed; inbound email and shared files are the usual routes. |
| **Multimodal (cross-modal) injection** | Instructions hidden in images, audio or video. | Now named in LLM01:2026; text filters do not see it. |
| **Invisible text (ASCII smuggling)** | Unicode characters that display as nothing but are read by the model. | Humans reviewing the content cannot see the attack. |
| **Jailbreak** | Input that bypasses a model's safety training. | Related to injection but aims at the model's rules, not the app's. |
| **Many-shot jailbreak** | Many fake example dialogues in a long context to shift behavior. | Long context windows make it practical. |
| **Adversarial suffix** | An optimized, odd-looking string that unlocks unwanted behavior. | Found automatically; often transfers between models. |
| **Adversarial example (evasion)** | Input changed slightly to make a model misclassify it. | Defeats ML-based detectors (malware, fraud, content filters). |
| **Hidden context exposure** | Extraction of system prompts, tool schemas, policy logic or workflow rules. | LLM08:2026 (was LLM07:2025 System Prompt Leakage). |
| **Sensitive information disclosure** | The model or app reveals data it should not: personal data, secrets, other tenants' data, reasoning traces, logs. | LLM02:2026 (also LLM02:2025). |
| **Improper output handling** | Model output used without validation by a browser, shell, database or API. | LLM10:2026 (was LLM05:2025); turns injection into XSS, SQLi, SSRF or RCE. |
| **Link and image exfiltration** | The model writes a URL that carries data to an attacker when rendered or clicked. | A common, quiet exfiltration channel; allowlist URLs. |
| **Unbounded consumption (denial of wallet)** | Inputs or loops that burn tokens, money or GPU time. | LLM06:2026 (was LLM10:2025). |
| **Excessive agency** | The model can do more than the task needs (too many tools, permissions or autonomy). | LLM03:2026 (was LLM06:2025). |
| **Misinformation (overreliance)** | People or systems act on false model output. | LLM07:2026 (was LLM09:2025). |

## 6. Data and training attacks

| Term | Meaning | Why security cares |
|---|---|---|
| **Data poisoning** | Inserting or changing training data to change behavior. Variants include label flipping and clean-label attacks (correctly labeled but crafted samples). | LLM05:2026 Data and Model Poisoning (was LLM04:2025). |
| **Model poisoning** | Changing weights or adapters directly. | Hard to detect by inspection; protect artifact integrity. |
| **Backdoor (trojan model)** | Hidden behavior that a specific trigger activates. | Can survive safety training; vet model sources. |
| **Trigger** | The input pattern that activates a backdoor. | Unknown triggers make backdoors hard to test for. |
| **RAG poisoning** | Planting content in a knowledge base so it is retrieved and trusted. | No training needed; anyone who can write to a source can do it. |
| **Preference (RLHF) poisoning** | Corrupting human feedback used for alignment. | Feedback pipelines need provenance and checks. |
| **Fine-tuning attack** | Using fine-tuning (even through a provider API) to remove safety behavior or add a backdoor. | Fine-tuning access is a privileged capability. |
| **Emergent misalignment** | Broad harmful behavior that appears after narrow fine-tuning. | Evaluate the whole model after any fine-tune. |
| **AI result poisoning** | Seeding public content so AI search and assistants give attacker-chosen answers to others. | The impersonated brand may never notice; users trust AI answers. |
| **Data provenance / lineage** | A record of where data came from and how it changed. | Needed to find and remove poisoned or unlawful data. |
| **AI lifecycle** | The stages from data collection to retirement. | Every stage has its own assets and threats ([lesson 01](01-ai-ml-llm-basics-for-security.md)). |

## 7. Model theft and privacy attacks

| Term | Meaning | Why security cares |
|---|---|---|
| **Model theft** | Stealing weights directly (storage, insider, compromised host). | Loses IP and lets attackers find weaknesses offline. |
| **Model extraction** | Copying a model's behavior by querying it. | Rate limits and usage monitoring are the defense. |
| **Distillation attack** | Large-scale extraction that trains a rival model on a model's outputs, often through many fake accounts. | Looks like normal traffic; needs account verification and analytics. |
| **Training-data extraction** | Getting a model to output memorized training text. | Personal data or secrets in training can leak. |
| **Membership inference** | Finding out whether a specific record was in the training data. | A privacy breach in itself for sensitive datasets. |
| **Attribute inference** | Inferring private attributes of people from model behavior. | Privacy harm without any direct leak. |
| **Model inversion** | Rebuilding representative inputs (for example faces) from a model. | Another route from a model back to its data. |
| **Embedding inversion** | Rebuilding text from embedding vectors. | Vector stores are as sensitive as their documents. |
| **Side channel (timing, cache)** | Learning secrets from response time or cache behavior. | Shared prompt or KV caches can leak whether others sent a prompt. |

## 8. AI supply chain

| Term | Meaning | Why security cares |
|---|---|---|
| **AI supply chain** | Everything you did not build: models, adapters, datasets, libraries, tools, MCP servers, providers. | LLM04:2026 Supply Chain (was LLM03:2025); ASI04 for agents. |
| **Model hub** | A public site for sharing models and datasets. | Anyone can upload; check publisher, format and scans. |
| **Malicious model file** | A model file that runs code when loaded, usually through Python pickle. | A model file can be code; use safe formats. |
| **safetensors** | A file format for weights that stores numbers only, without code. | Removes the "code on load" problem. |
| **Model provenance** | Verifiable history of where a model came from and how it was built. | Lets you trust, or reject, an artifact. |
| **Model signing** | Cryptographic signatures on model artifacts. | Detects tampering between build and deployment. |
| **Model card** | A document describing a model's purpose, data, limits and evaluations. | Governance evidence; also tells you what was *not* tested. |
| **AI bill of materials (AI-BOM)** | An inventory of models, datasets and components in an AI system (for example in CycloneDX or SPDX format). | Lets you find affected systems when a component is compromised. |
| **Package hallucination (slopsquatting)** | Models invent package names; attackers register them with malicious code. | AI-generated install commands need verification. |
| **Vibe coding** | Building software mainly by prompting an AI and accepting its code with little review. | Insecure code ships fast; review and scanning still apply. |
| **Shadow AI** | AI tools or models used without approval or inventory. | Data leaves through channels nobody monitors. |
| **Third-party AI risk** | Risk from vendors' AI features and providers' models. | Contracts must cover data use, retention, incidents and changes. |

## 9. Agentic AI and MCP risks

The OWASP Top 10 for Agentic Applications (ASI01–ASI10, published December 2025) and the OWASP MCP Top 10 (beta) name these risks; verify the current lists at the source.

| Term | Meaning | Why security cares |
|---|---|---|
| **Agent goal hijack** | Injected content changes what the agent is trying to achieve. | ASI01. The agent keeps working, for the attacker. |
| **Tool misuse** | An agent uses legitimate tools in harmful ways. | ASI02. Permissions are right, but the use is wrong. |
| **Identity and privilege abuse** | An agent's credentials or delegated rights are misused or too broad. | ASI03. Agents need their own scoped, short-lived identities. |
| **Agent identity (non-human identity)** | The credential an agent acts with, ideally separate from users and other agents. | Without it, actions cannot be authorized or audited. |
| **Delegated authority** | Permission an agent holds on behalf of a user. | Must be scoped, time-limited and revocable. |
| **Agentic supply chain** | Third-party tools, plugins, MCP servers, prompts and agents an agent depends on. | ASI04. One bad component compromises every agent using it. |
| **Unexpected code execution** | An agent writes or triggers code that runs where it should not. | ASI05. Sandboxes and allowlists are required. |
| **Memory and context poisoning** | Planting false or malicious content in an agent's memory or context. | ASI06. Gives persistence across sessions. |
| **Insecure inter-agent communication** | Agent messages that are not authenticated, integrity-protected or validated. | ASI07. One agent can spoof or manipulate another. |
| **Cascading failure** | One error or compromise spreading through connected agents. | ASI08. Validate between steps; add circuit breakers. |
| **Human-agent trust exploitation** | An agent uses its credibility to get people to approve harmful actions. | ASI09. Approval screens must show facts, not the agent's summary. |
| **Rogue agent** | An agent acting outside its intended purpose, through compromise or misalignment. | ASI10. Needs monitoring and a kill switch. |
| **AI worm** | A self-replicating injection that spreads through content agents read and send. | Connected assistants create propagation paths. |
| **Tool poisoning** | Malicious instructions hidden in a tool's description or metadata. | MCP03; the model reads descriptions as trusted context. |
| **MCP rug pull** | A tool server changes its tool definitions after it was approved. | Pin and re-verify tool definitions. |
| **Token mismanagement** | Credentials exposed in configs, logs, prompts or passed through MCP servers. | MCP01; a stolen token acts as the user. |
| **Shadow MCP server** | An MCP server running without approval or inventory. | MCP09; an unmonitored path to data and actions. |

## 10. Attacks that use AI

| Term | Meaning | Why security cares |
|---|---|---|
| **LLMjacking** | Using stolen cloud credentials or API keys to consume someone else's AI services. | Credential theft, cost and abuse in one; protect AI keys like admin keys. |
| **AI-orchestrated cyberattack** | An intrusion where AI agents perform most steps, with humans directing key decisions. | Attack speed and scale rise; detection must keep up. |
| **AI-assisted vulnerability discovery** | Using AI to find bugs in code or systems. | Helps defenders and attackers; patch windows shrink. |
| **AI-enabled phishing** | Phishing written or personalized by AI. | Better language and scale; spelling mistakes are no longer a signal. |
| **Deepfake / voice cloning** | Synthetic video or audio of real people. | Defeats "call back and check" if the callback can be faked; use out-of-band verification. |
| **Synthetic persona** | A fake identity built with AI-generated photos, documents and profiles. | Hiring and onboarding become insider-risk entry points. |
| **LLM-powered malware** | Malware that queries an LLM at runtime to decide or generate actions. | Behavior changes per run; detection must look at behavior. |

## 11. Defences and controls

| Term | Meaning | Why security cares |
|---|---|---|
| **Defence in depth** | Several independent layers so one failure is not enough. | Essential because model-level defenses are probabilistic. |
| **Hard vs soft control** | Deterministic, testable code or config vs probabilistic measures (prompts, classifiers). | Hard controls hold the line; soft ones lower the odds. |
| **Guardrails** | Checks around a model: input and output filters, moderation classifiers, policy engines. | Useful layers; can be bypassed; do not rely on one alone. |
| **Input / output filtering** | Checking content before it reaches the model or after it leaves. | Output filtering is closer to impact; both are soft against novel attacks. |
| **Instruction hierarchy** | Training a model to rank instructions by source (system > user > tools and documents). | Lowers injection success; not a guarantee. |
| **Spotlighting** | Marking untrusted text (delimiters, encoding) so the model treats it as data. | Soft; helps, does not stop determined attacks. |
| **Injection-resistant design patterns** | Designs that limit what an injection can do: dual LLM, plan-then-execute, CaMeL-style capability tracking. | Deterministic protection that holds even when injection succeeds. |
| **Dual LLM / quarantine pattern** | A model that reads untrusted content has no tools; a privileged model never sees raw untrusted content. | Breaks the lethal trifecta by design. |
| **Permission-aware retrieval** | Retrieval that filters by the requesting user's rights before ranking. | Stops RAG from leaking documents. |
| **Tool broker / policy enforcement point** | Code between the model and tools that validates and authorizes every call. | Where authorization really happens. |
| **Sandboxing** | Running code or tools in an isolated, limited environment. | Contains unexpected code execution. |
| **Egress control** | Restricting where systems can send network traffic. | Blocks exfiltration and SSRF to metadata services. |
| **Rate limiting / quotas / token budgets** | Caps on requests, tokens and spend. | Stops denial of wallet and slows extraction. |
| **AI observability** | Logging and tracing prompts, retrievals, tool calls and decisions. | Needed to detect, investigate and prove. |
| **Kill switch** | A fast way to disable a model, tool or agent. | Limits damage during an incident. |
| **AI red teaming** | Adversarial testing of an AI system by people and tools. | Finds what checklists miss. |
| **Model evaluation (evals)** | Systematic tests of model behavior, including safety and security. | Run on every model, prompt, fine-tune or quantization change. |
| **Adversarial training** | Training on attack examples to improve robustness. | Helps against known attacks; new ones still appear. |
| **Differential privacy** | Training that mathematically limits how much any one record affects the model. | Reduces memorization and membership inference. |
| **Confidential computing** | Hardware-protected memory for data in use. | Protects prompts and weights from the host. |
| **Watermarking and content provenance** | Marking AI-generated content or recording its origin (for example C2PA). | Helps detect synthetic media; not fully robust. |
| **AI incident response** | Preparing for, detecting, containing and learning from AI incidents. | AI incidents need AI-specific playbooks (prompts, tools, models). |

## 12. Governance, risk and frameworks

| Term | Meaning | Why security cares |
|---|---|---|
| **AI governance** | The policies, roles and processes that decide how AI is used. | Gives security a mandate and owners. |
| **Responsible AI** | Principles such as fairness, transparency, accountability, privacy and safety. | Many security controls are also responsible-AI evidence. |
| **AI inventory** | A list of AI systems, models, data and owners. | You cannot protect what you have not listed. |
| **AI risk assessment / impact assessment** | Evaluating risks of an AI system / its effects on people and society (ISO/IEC 42005 covers impact assessment). | Decides controls and approvals. |
| **Explainability and transparency** | Being able to explain how a system works or reached an output, and telling people when AI is used. | Supports audits, disputes and legal duties. |
| **AI acceptable use policy** | Rules for staff use of AI tools. | Main control against shadow AI and data leakage. |
| **AI assurance / AI audit** | Independent checking that AI controls exist and work. | Requires evidence, not intentions. |
| **NIST AI RMF** | US voluntary framework (Govern, Map, Measure, Manage), with a Generative AI Profile (NIST AI 600-1). | Common structure for AI risk programs. Not a law. |
| **NIST AI 100-2** | NIST's taxonomy and terminology of adversarial ML attacks. | Shared vocabulary for attack types. |
| **ISO/IEC 42001** | A certifiable AI management-system standard. | Organizational controls and audits. Not a law. |
| **ISO/IEC 23894** | Guidance on AI risk management, aligned with ISO 31000. | How to run AI risk management. |
| **ISO/IEC 27090** | International guidance on security threats to AI systems (reported as published in 2026; verify the status). | Technical security reference to map controls to. |
| **EU AI Act** | The EU law that regulates AI by risk level (Regulation (EU) 2024/1689, amended by the 2026 Digital Omnibus; verify dates at the source). | Legal duties for providers and deployers. |
| **Provider and deployer** | EU AI Act roles: who places an AI system on the market vs who uses it. | Your duties depend on your role. |
| **High-risk AI system** | EU AI Act category with strict duties (for example in employment or credit). | Triggers risk management, logging, human oversight and documentation. |
| **General-purpose AI model (GPAI)** | EU AI Act term for broad models like LLMs, with their own duties for providers. | Affects foundation-model providers and the information they must give you. |
| **MITRE ATLAS** | A knowledge base of tactics, techniques and case studies of attacks on AI systems. | Shared IDs for threat models, red teams and detections. |
| **OWASP Top 10 for LLM and Agentic Applications** | Community lists of the top LLM application risks (2026 edition) and agentic risks (ASI01–ASI10). | A coverage checklist, not a threat model. Not a law. |
| **OWASP MCP Top 10** | Community list (beta) of risks in MCP deployments, MCP01–MCP10. | Checklist for tool-server designs. |
| **CSA MAESTRO** | Cloud Security Alliance threat-modeling framework for agentic AI, with seven layers. | Fits multi-agent systems better than STRIDE alone ([lesson 03](03-ai-threat-modeling.md)). |

---

*Source note: section structure and term selection were informed by *The AI Security Glossary* (in the owner's document library), the ISC2 AI Security study guide (Appendix B), OWASP and NIST publications. All definitions are written in our own words. Framework names, numbers and dates change; verify at the source before you rely on them.*
