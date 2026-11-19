# Chapter 2: Understanding and Attacking LLMs

> **Time:** ~35 to 45 hours with labs · **Outcome:** you can explain how LLMs work and how GPT and BERT differ, describe foundation, fine-tuned and RAG-augmented systems, map attacks to the 14 MITRE ATLAS tactics, brief a team on criminal LLM tools, and you have built and attacked small LLM systems in ten hands-on labs.
> **Prerequisites:** [Chapter 1](../ch1-introduction-to-ai-security/README.md). Wording follows the course syllabus; the explanations are written independently.

## Syllabus coverage

Every line of the chapter syllabus, in order. Lab folders in `labs/` hold offline versions with tests; heavy labs also have a Colab notebook in `notebooks/` (not executed by the repo author: run in Colab or in your course lab; versions may need updates).

| Syllabus item | Where to study | Lab |
|---|---|---|
| Introduction to Large Language Models | [01 LLM intro](01-llm-intro-gpt-bert-training-and-use-cases.md), sections 2.1 to 2.3 | [`labs/01-simple-chatbot`](labs/01-simple-chatbot/) |
| &nbsp;&nbsp;Definition of Large Language Models | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.1 | n/a |
| &nbsp;&nbsp;How LLMs work | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.2 · [Repo 01b](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md) | [`labs/02-tokenizers`](labs/02-tokenizers/) · [repo tiny_llm lab](../../01-ai-security-fundamentals/lab/tiny_llm.py) |
| &nbsp;&nbsp;Importance and impact of LLMs in AI | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.3 | n/a |
| Understanding LLMs | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.4 | n/a |
| &nbsp;&nbsp;GPT (Generative Pre-trained Transformer) | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.4 (figure [`caisp-ch2-gpt-vs-bert.svg`](../../images/caisp-ch2-gpt-vs-bert.svg)) | [`labs/01-simple-chatbot`](labs/01-simple-chatbot/), [`labs/03-summarizer`](labs/03-summarizer/) |
| &nbsp;&nbsp;BERT (Bidirectional Encoder Representations from Transformers) | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.4 | [`labs/08-sentiment-analysis`](labs/08-sentiment-analysis/) |
| Training and Augmenting LLMs | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), sections 2.5 and 2.6 | [`labs/04-fine-tuned-model`](labs/04-fine-tuned-model/), [`labs/06-rag-system`](labs/06-rag-system/) |
| &nbsp;&nbsp;Foundational model and fine-tuned model | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.5 · [Repo 01b (LoRA, QLoRA)](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md) | [`labs/04-fine-tuned-model`](labs/04-fine-tuned-model/) · [notebook](notebooks/04-fine-tuned-model.ipynb) |
| &nbsp;&nbsp;Retrieval augmented generation | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.6 · [Chapter 1 lesson 03](../ch1-introduction-to-ai-security/03-core-components-and-ml-concepts.md) · [Repo module 03: RAG security](../../03-rag-security/README.md) | [`labs/06-rag-system`](labs/06-rag-system/) |
| Use Cases of LLMs | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.7 | [`labs/01-simple-chatbot`](labs/01-simple-chatbot/), [`labs/03-summarizer`](labs/03-summarizer/), [`labs/08-sentiment-analysis`](labs/08-sentiment-analysis/) |
| &nbsp;&nbsp;Text Generation | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.7 | [`labs/01-simple-chatbot`](labs/01-simple-chatbot/) |
| &nbsp;&nbsp;Text Understanding | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.7 | [`labs/03-summarizer`](labs/03-summarizer/), [`labs/08-sentiment-analysis`](labs/08-sentiment-analysis/) |
| &nbsp;&nbsp;Conversational AI | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.7 | [`labs/01-simple-chatbot`](labs/01-simple-chatbot/) · [chapter 1 chatbot lab](../ch1-introduction-to-ai-security/labs/llm-chatbot/) |
| Attack Tactics and Techniques | [02 ATT&CK vs ATLAS and the 14 tactics](02-attck-vs-atlas-and-the-14-tactics.md) · [Repo lesson 03 (threat modelling, ATLAS)](../../01-ai-security-fundamentals/03-ai-threat-modeling.md) | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Mitre ATT&CK | [02](02-attck-vs-atlas-and-the-14-tactics.md), sections 2.1 and 2.2 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Mitre ATLAS matrix | [02](02-attck-vs-atlas-and-the-14-tactics.md), sections 2.2 and 2.3 (figure [`caisp-ch2-atlas-tactic-flow.svg`](../../images/caisp-ch2-atlas-tactic-flow.svg)) | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Reconnaissance tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 1 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Resource development tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 2 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Initial access tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 3 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;ML model access tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 4 (newer name: AI Model Access) | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Execution tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 5 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Persistence tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 6 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Privilege escalation tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 7 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Defense evasion tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 8 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) · [`labs/07-textattack-adversarial`](labs/07-textattack-adversarial/) |
| &nbsp;&nbsp;Credential access tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 9 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Discovery tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 10 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Collection tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 11 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;ML attack staging | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 12 (newer name: AI Attack Staging; a later rename is reported, verify) | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) · [`labs/07-textattack-adversarial`](labs/07-textattack-adversarial/) · [`labs/09-backdoor-attacks`](labs/09-backdoor-attacks/) |
| &nbsp;&nbsp;Exfiltration tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 13 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| &nbsp;&nbsp;Impact tactic | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactic 14 | [`labs/00-atlas-mapping`](labs/00-atlas-mapping/) |
| Real-World LLM attack tools on the internet | [03 Malicious LLM tools: threat-intel briefing](03-malicious-llm-tools-threat-intel.md) | n/a (briefing and action-plan exercise) |
| &nbsp;&nbsp;XXXGPT | [03](03-malicious-llm-tools-threat-intel.md), section 2.1 | n/a |
| &nbsp;&nbsp;WormGPT | [03](03-malicious-llm-tools-threat-intel.md), section 2.1 | n/a |
| &nbsp;&nbsp;FraudGPT | [03](03-malicious-llm-tools-threat-intel.md), section 2.1 | n/a |
| Hands-On Exercises | Labs below | See rows below |
| &nbsp;&nbsp;Creating a Simple Chatbot | [Chapter 1 chatbot lab](../ch1-introduction-to-ai-security/labs/llm-chatbot/README.md) (warm-up) | [`labs/01-simple-chatbot`](labs/01-simple-chatbot/) |
| &nbsp;&nbsp;Exploring How Tokenizers Work | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.2 · [Repo 01b](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md) | [`labs/02-tokenizers`](labs/02-tokenizers/) |
| &nbsp;&nbsp;Building a Summarizer Tool Using an LLM | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.7 | [`labs/03-summarizer`](labs/03-summarizer/) |
| &nbsp;&nbsp;Building a Fine-tuned Model | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.5 | [`labs/04-fine-tuned-model`](labs/04-fine-tuned-model/) · [notebook](notebooks/04-fine-tuned-model.ipynb) |
| &nbsp;&nbsp;Building a Simple Website Scraper | [Repo prompt injection (indirect injection from web content)](../../02-llm-security/prompt-injection/README.md) | [`labs/05-web-scraper`](labs/05-web-scraper/) |
| &nbsp;&nbsp;Building a RAG System | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.6 · [Repo module 03](../../03-rag-security/README.md) | [`labs/06-rag-system`](labs/06-rag-system/) |
| &nbsp;&nbsp;Attacking an LLM Model using TextAttack | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactics 8 and 12 | [`labs/07-textattack-adversarial`](labs/07-textattack-adversarial/) · [notebook](notebooks/07-textattack-adversarial.ipynb) |
| &nbsp;&nbsp;Performing Sentiment Analysis Using an LLM | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.7 | [`labs/08-sentiment-analysis`](labs/08-sentiment-analysis/) · [notebook](notebooks/08-sentiment-analysis.ipynb) |
| &nbsp;&nbsp;Backdoor Attacks using BackdoorBox | [02](02-attck-vs-atlas-and-the-14-tactics.md), Tactics 6 and 12 · [Repo model-threats](../../02-llm-security/model-threats/README.md) | [`labs/09-backdoor-attacks`](labs/09-backdoor-attacks/) · [notebook](notebooks/09-backdoor-attacks.ipynb) |
| &nbsp;&nbsp;Building a Speech To Text System | [01](01-llm-intro-gpt-bert-training-and-use-cases.md), section 2.7 (text understanding) | [`labs/10-speech-to-text`](labs/10-speech-to-text/) · [notebook](notebooks/10-speech-to-text.ipynb) |

The ten hands-on labs and notebooks are built separately in `labs/` and `notebooks/`. The ATLAS mapping lab ([`labs/00-atlas-mapping`](labs/00-atlas-mapping/)) is the lab for the tactics lesson.

## Learning order

1. Lesson [01](01-llm-intro-gpt-bert-training-and-use-cases.md), then labs 01 and 02 (chatbot, tokenizers).
2. Labs 03 (summarizer), 05 (scraper) and 06 (RAG), alongside [Module 03: RAG security](../../03-rag-security/README.md).
3. Lab 04 (fine-tuning) and its notebook, with [repo 01b](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md) open.
4. Lesson [02](02-attck-vs-atlas-and-the-14-tactics.md): read the tactics one per day if you are short on time, then do [`labs/00-atlas-mapping`](labs/00-atlas-mapping/).
5. Labs 07 (TextAttack), 08 (sentiment), 09 (backdoor) and 10 (speech to text).
6. Lesson [03](03-malicious-llm-tools-threat-intel.md) and the action-plan exercise.
7. Answer the Q&A below without looking.

Run the tests of the lesson lab:

```bash
.venv/Scripts/python -m pytest caisp-course/ch2-understanding-and-attacking-llms/labs/00-atlas-mapping
```

## Exam tips for this chapter

- **Memorise the 14 tactics in order** (Reconnaissance to Impact) and have one AI-flavoured example per tactic ready. A good memory hook: *find, build, get in, reach the model, run, stay, rise, hide, steal keys, look around, gather, prepare, take out, harm*.
- Know the **two AI-specific tactics** (Model Access and Attack Staging) and the rename to "AI ...". Say "verify at atlas.mitre.org" when you are unsure about IDs; do not invent technique IDs.
- Know the difference **tactic (goal) versus technique (method)**, and **ATT&CK versus ATLAS**.
- Be able to compare **GPT versus BERT** and **fine-tuning versus RAG** in a table from memory.
- For the malicious LLM tools, answer in a **defender** frame: what they are, what they change (phishing quality and scale), what controls help. Do not describe usage.
- For hands-on labs, know the *idea* of each: tokenizer pieces and IDs, summariser with untrusted text, fine-tuning data quality, scraper as an indirect-injection source, RAG retrieval, adversarial text attacks, backdoor trigger, speech-to-text as an input channel.
- Mention **safety**: attacks only on systems you own, canaries and harmless payloads.

## Interview and exam Q&A (15)

<details><summary><b>Q1. What is an LLM and how does it generate text?</b></summary>

A very large transformer network trained to predict the next token. It turns text into tokens and embeddings, runs attention layers, outputs probabilities for the next token, samples one, appends it and repeats.
</details>

<details><summary><b>Q2. GPT versus BERT?</b></summary>

GPT: decoder-only, autoregressive, generates text and sees only earlier tokens. BERT: encoder, masked language model, sees both sides, produces embeddings for classification and search.
</details>

<details><summary><b>Q3. Foundation model versus fine-tuned model, and a risk of fine-tuning?</b></summary>

A foundation model is a broad pre-trained base; a fine-tuned model is adapted to a task with extra data. Fine-tuning can weaken safety behaviour, memorise sensitive data, or be poisoned.
</details>

<details><summary><b>Q4. When RAG, when fine-tuning?</b></summary>

RAG for fresh, private, citable, deletable facts. Fine-tuning for tone, format and skills. Often combined.
</details>

<details><summary><b>Q5. Why is prompt injection possible?</b></summary>

Instructions and data share one text channel, and attention has no hard trust boundary between them. So untrusted text can act as an instruction.
</details>

<details><summary><b>Q6. What is MITRE ATLAS?</b></summary>

A knowledge base of tactics, techniques and case studies for attacks on AI systems, structured like ATT&CK and linked to it.
</details>

<details><summary><b>Q7. Which ATLAS tactics are AI-specific and what are their newer names?</b></summary>

ML Model Access and ML Attack Staging, renamed AI Model Access and AI Attack Staging in newer data; a further rename of the staging tactic is reported (verify at the source).
</details>

<details><summary><b>Q8. Give one example for each of Initial Access, Execution and Persistence against an LLM app.</b></summary>

Initial Access: a document with hidden instructions that the system ingests. Execution: the model calls a tool with attacker-chosen arguments. Persistence: the instruction is stored in long-term memory or the RAG index.
</details>

<details><summary><b>Q9. How is Exfiltration different in an LLM app?</b></summary>

Data can leave through the model's answer, through links or markdown images that the client renders, through tool calls to external services, or through the inference API (model extraction), besides classic file copying.
</details>

<details><summary><b>Q10. What does ML Attack Staging look like and how do you see it?</b></summary>

Building a proxy model, crafting adversarial data and verifying the attack offline. You see its footprint as many systematic probing queries, so monitor query volume and patterns and limit output detail.
</details>

<details><summary><b>Q11. How do you map an incident to ATLAS?</b></summary>

Break it into attacker actions, give each one tactic (the goal), note the technique (the method), tag it with the ATLAS version, and cross-reference ATT&CK for the classic IT steps. Use it to find where controls could have broken the chain.
</details>

<details><summary><b>Q12. What are WormGPT and FraudGPT, in a defender's words?</b></summary>

Criminal-marketed LLM services reported in 2023 for phishing and fraud content, often wrappers around public or open models, sometimes scams. They mainly increase the quality and scale of social engineering.
</details>

<details><summary><b>Q13. How do you defend against AI-written phishing?</b></summary>

Email authentication, phishing-resistant MFA, link sandboxing, out-of-band verification of payment changes, behaviour-based detection and updated awareness training that stops relying on bad grammar.
</details>

<details><summary><b>Q14. How would you attack-test a text classifier safely?</b></summary>

Use an adversarial text attack library against your own model in a lab (word swaps, typos), measure the drop in accuracy, then add defences (adversarial training, input normalisation) and retest. Only on systems you own.
</details>

<details><summary><b>Q15. A backdoored model passes all your accuracy tests. How is that possible and what do you do?</b></summary>

A backdoor changes behaviour only when a trigger appears, so normal inputs behave normally. Check provenance, scan files, test with trigger candidates, compare against a trusted baseline, and prefer trusted sources and signed artifacts.
</details>

## References

- MITRE ATLAS: <https://atlas.mitre.org> · MITRE ATT&CK: <https://attack.mitre.org>
- Vaswani et al. (2017); Devlin et al. (2018); Lewis et al. (2020); Hu et al. (2021).
- OWASP GenAI Security Project: <https://genai.owasp.org>
- Repo: [module 02 LLM security](../../02-llm-security/README.md), [module 03 RAG security](../../03-rag-security/README.md)
- Previous: [Chapter 1](../ch1-introduction-to-ai-security/README.md) · Next: Chapter 3, LLM Top 10 vulnerabilities (`../ch3-llm-top-10-vulnerabilities/`)
