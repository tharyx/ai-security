# Chapter 1: Introduction to AI Security

> **Time:** ~25 to 30 hours with labs · **Outcome:** you can explain what AI, ML, deep learning and RAG are, how AI systems are built (algorithms and models, data, compute), and the main security risk of each part, and you have built and attacked a small LLM chatbot.
> **Prerequisites:** basic Python. No ML background needed. Wording follows the course syllabus; this repo's own explanations are written independently in simple English.

## Syllabus coverage

Every line of the chapter syllabus, in order. "Where to study" links to a lesson in this chapter or to an existing repo lesson.

| Syllabus item | Where to study | Lab |
|---|---|---|
| Course Introduction (About the course, syllabus, and how to approach it) | [00 How to approach this course](00-how-to-approach-this-course.md), sections 1 to 3 | n/a |
| About Certification and how to approach it | [00 How to approach this course](00-how-to-approach-this-course.md), section 4 | n/a |
| Course Lab Environment | [00 How to approach this course](00-how-to-approach-this-course.md), section 3 | Course lab environment (provided by the course); offline twins in this chapter |
| Lifetime course support (Mattermost) | [00 How to approach this course](00-how-to-approach-this-course.md), section 5 | n/a |
| An overview of AI Security | [01 AI basics, history and evolution](01-ai-basics-history-and-evolution.md), section 2.1 · [Repo module 01 overview](../../01-ai-security-fundamentals/README.md) | n/a |
| Basics of AI and ML | [01 AI basics, history and evolution](01-ai-basics-history-and-evolution.md) and [03 Core components and ML concepts](03-core-components-and-ml-concepts.md) | [`labs/learning-paradigms`](labs/learning-paradigms/) |
| &nbsp;&nbsp;What is AI? | [01](01-ai-basics-history-and-evolution.md), section 2.2 | n/a |
| &nbsp;&nbsp;History and evolution of AI | [01](01-ai-basics-history-and-evolution.md), section 2.3 (timeline image [`caisp-ch1-ai-timeline.svg`](../../images/caisp-ch1-ai-timeline.svg)) | n/a |
| &nbsp;&nbsp;Key concepts in AI | [01](01-ai-basics-history-and-evolution.md), section 2.4 · [Repo glossary](../../01-ai-security-fundamentals/glossary.md) | n/a |
| Types of AI | [02 Types of AI and learning paradigms](02-types-of-ai-and-learning-paradigms.md) | [`labs/learning-paradigms`](labs/learning-paradigms/) |
| &nbsp;&nbsp;Narrow AI vs. General AI | [02](02-types-of-ai-and-learning-paradigms.md), section 2.1 · [Repo 01b, section 2.1](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md) | n/a |
| &nbsp;&nbsp;Supervised Learning | [02](02-types-of-ai-and-learning-paradigms.md), section 2.3 | [`labs/learning-paradigms`](labs/learning-paradigms/) (`NearestCentroid`) |
| &nbsp;&nbsp;Unsupervised Learning | [02](02-types-of-ai-and-learning-paradigms.md), section 2.4 | [`labs/learning-paradigms`](labs/learning-paradigms/) (`kmeans`) |
| &nbsp;&nbsp;Reinforcement Learning | [02](02-types-of-ai-and-learning-paradigms.md), section 2.5 | [`labs/learning-paradigms`](labs/learning-paradigms/) (`Bandit`, `q_learning`) |
| &nbsp;&nbsp;Natural Language Processing (NLP) | [02](02-types-of-ai-and-learning-paradigms.md), section 2.6 | [`labs/llm-chatbot`](labs/llm-chatbot/); tokens in [repo tiny_llm lab](../../01-ai-security-fundamentals/lab/tiny_llm.py) |
| &nbsp;&nbsp;Computer Vision | [02](02-types-of-ai-and-learning-paradigms.md), section 2.7 · [04](04-deep-learning-neural-networks-and-cnns.md) | [`labs/cnn-convolution`](labs/cnn-convolution/) |
| Core Components of AI Systems | [03 Core components and ML concepts](03-core-components-and-ml-concepts.md), section 2.1 | n/a |
| &nbsp;&nbsp;Algorithms and Models | [03](03-core-components-and-ml-concepts.md), section 2.1 · [Repo model-threats](../../02-llm-security/model-threats/README.md) | n/a |
| &nbsp;&nbsp;Data | [03](03-core-components-and-ml-concepts.md), section 2.1 · [Repo model-threats (poisoning)](../../02-llm-security/model-threats/README.md) | [`labs/learning-paradigms`](labs/learning-paradigms/) (label flipping, poisoning) |
| &nbsp;&nbsp;Computing Power | [03](03-core-components-and-ml-concepts.md), section 2.1 · [Repo security-testing (unbounded consumption)](../../02-llm-security/security-testing/README.md) | [`labs/llm-chatbot`](labs/llm-chatbot/) (rate and size limits) |
| Introduction to Machine Learning | [03 Core components and ML concepts](03-core-components-and-ml-concepts.md), sections 2.2 to 2.5 | [`labs/learning-paradigms`](labs/learning-paradigms/) |
| &nbsp;&nbsp;What is Machine Learning? | [03](03-core-components-and-ml-concepts.md), section 2.2 | n/a |
| &nbsp;&nbsp;Differences between AI and ML | [03](03-core-components-and-ml-concepts.md), section 2.3 | n/a |
| &nbsp;&nbsp;Key ML concepts | [03](03-core-components-and-ml-concepts.md), section 2.4 | [`labs/learning-paradigms`](labs/learning-paradigms/) (metrics, overfitting) |
| Retrieval Augmented Generation | [03](03-core-components-and-ml-concepts.md), section 2.6 (overview) · [Repo module 03: RAG security](../../03-rag-security/README.md) (full study) · [Chapter 2 lesson 01](../ch2-understanding-and-attacking-llms/01-llm-intro-gpt-bert-training-and-use-cases.md) | [Repo RAG labs](../../03-rag-security/README.md); chapter 2 [`labs/06-rag-system`](../ch2-understanding-and-attacking-llms/labs/06-rag-system/) |
| Basics of Deep Learning | [04 Deep learning, neural networks and CNNs](04-deep-learning-neural-networks-and-cnns.md) | [`labs/cnn-convolution`](labs/cnn-convolution/) |
| &nbsp;&nbsp;What is Deep Learning? | [04](04-deep-learning-neural-networks-and-cnns.md), section 2.1 | n/a |
| &nbsp;&nbsp;Introduction to Neural Networks | [04](04-deep-learning-neural-networks-and-cnns.md), section 2.2 · [Repo 01b](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md) | [Repo tiny_llm lab](../../01-ai-security-fundamentals/lab/tiny_llm.py) |
| &nbsp;&nbsp;Brief overview of Convolutional Neural Networks (CNNs) | [04](04-deep-learning-neural-networks-and-cnns.md), sections 2.3 to 2.5 | [`labs/cnn-convolution`](labs/cnn-convolution/) |
| Hands-On Exercise: Building a Chatbot Using an LLM | [`labs/llm-chatbot/README.md`](labs/llm-chatbot/README.md) | [`labs/llm-chatbot`](labs/llm-chatbot/) · optional Colab [`notebooks/llm-chatbot.ipynb`](notebooks/llm-chatbot.ipynb) |

## Learning order

1. Read [00](00-how-to-approach-this-course.md) once. Set up the repo labs.
2. Watch the course sections for the admin items and "An overview of AI Security".
3. Lesson [01](01-ai-basics-history-and-evolution.md) (AI basics and history), then lesson [02](02-types-of-ai-and-learning-paradigms.md) plus the `learning-paradigms` lab.
4. Lesson [03](03-core-components-and-ml-concepts.md), then skim [Module 03 RAG overview](../../03-rag-security/README.md) sections 1 and 2.
5. Lesson [04](04-deep-learning-neural-networks-and-cnns.md) plus the `cnn-convolution` lab. For the language side, read [repo lesson 01b](../../01-ai-security-fundamentals/01b-inside-the-llm-transformers-inference-and-training.md).
6. Do the `llm-chatbot` exercise in the course lab, then the offline lab here.
7. Answer the Q&A below without looking.

Run all chapter 1 tests:

```bash
.venv/Scripts/python -m pytest caisp-course/ch1-introduction-to-ai-security
```

## Exam tips for this chapter

- Expect **definition and relationship questions**: AI vs ML vs deep learning vs generative AI; narrow vs general AI; supervised vs unsupervised vs reinforcement. Learn the one-sentence version of each, then an example.
- Always add the **security angle**: data → poisoning, models → theft and malicious files, compute → denial of service and cost, vision → adversarial examples and patches, chatbots → prompt injection and leakage.
- Know the **CIA triad mapped to AI** (leakage, tampering, availability).
- For RAG know the four steps (index, retrieve, augment, generate) and "similarity is not authorisation".
- Be able to explain a **convolution** with a tiny example, and why accuracy is a poor metric for rare attacks.
- Be careful: terms like "ML Model Access" or the OWASP list names differ between 2023 and later versions. Learn the course's names and know the newer ones exist (see chapter 3).
- If the exam is practical, practise the chatbot lab until you can build it, attack it and fix it from memory.

## Interview and exam Q&A (15)

<details><summary><b>Q1. What is AI security?</b></summary>

Protecting AI systems (data, models, prompts, tools, infrastructure) from attack and misuse, plus understanding how attackers and defenders use AI. It combines classic security with AI-specific risks such as poisoning, prompt injection and model theft.
</details>

<details><summary><b>Q2. How do AI, machine learning and deep learning relate?</b></summary>

AI is the widest field. ML is the subset that learns from data. Deep learning is the subset of ML using many-layer neural networks. LLMs are deep-learning models.
</details>

<details><summary><b>Q3. Narrow AI or general AI: which exists today?</b></summary>

Narrow AI only. LLMs are narrow systems that feel general. AGI is theoretical.
</details>

<details><summary><b>Q4. Compare supervised, unsupervised and reinforcement learning and give an attack on each.</b></summary>

Supervised: labeled data, predicts labels; attack: label flipping and poisoning, evasion. Unsupervised: finds structure without labels; attack: shifting the notion of normal, hiding near cluster centres. Reinforcement: learns from rewards; attack: reward hacking and poisoned feedback.
</details>

<details><summary><b>Q5. What are the three core components of an AI system and their risks?</b></summary>

Algorithms and models (theft, tampering, malicious files), data (poisoning, privacy leakage), computing power (denial of service, denial of wallet, isolation failures).
</details>

<details><summary><b>Q6. What is overfitting and what is the security impact?</b></summary>

The model memorises its training data and generalises badly. Memorisation can leak training data, and an overfit model is often easier to attack.
</details>

<details><summary><b>Q7. Why is accuracy not enough for a detection model?</b></summary>

With rare attacks, a model that never alerts can still have very high accuracy. Use precision, recall and F1.
</details>

<details><summary><b>Q8. Explain training versus inference and the risks of each.</b></summary>

Training builds the model (poisoning, backdoors, data leakage, supply chain). Inference uses it (prompt injection, evasion, extraction, denial of service).
</details>

<details><summary><b>Q9. What is RAG and why is it popular?</b></summary>

Retrieval Augmented Generation: retrieve relevant documents and add them to the prompt so the LLM answers from current, private data without retraining. Risks: poisoned documents, access control at retrieval, indirect injection, leakage.
</details>

<details><summary><b>Q10. What does a convolution do in a CNN?</b></summary>

A small learned filter slides over the image, multiplying and summing at each position to build a feature map showing where its pattern appears. Weights are shared across positions.
</details>

<details><summary><b>Q11. What is an adversarial example and how is it defended?</b></summary>

A small, deliberate input change that flips the model's output. Defences: adversarial training, input checks, ensembles, monitoring, human review for critical decisions. No single defence is complete.
</details>

<details><summary><b>Q12. How does a chatbot "remember" a conversation?</b></summary>

It does not: the app sends the system prompt and the previous messages with every request. Memory therefore costs tokens and can carry injected text forward.
</details>

<details><summary><b>Q13. Name four security risks of a naive LLM chatbot and a hard control for each.</b></summary>

Prompt injection (limit capabilities, no secrets in prompts), leakage (output filter, DLP), unbounded input/memory (size caps, memory window), flooding (rate limits and budgets).
</details>

<details><summary><b>Q14. Why does "put it in the system prompt" not protect a secret?</b></summary>

The model can be induced to repeat its prompt, and the prompt is sent in plain text to the provider. Keep secrets out of prompts and enforce access in code.
</details>

<details><summary><b>Q15. Explain to an executive why AI security needs its own attention.</b></summary>

AI systems learn behaviour from data and accept natural-language input, so attackers can change behaviour through data or text, not only through code. Costs and data exposure can also grow quickly. We need inventory, testing and controls built for these risks.
</details>

## References

- [MITRE ATLAS](https://atlas.mitre.org) · [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) · [OWASP GenAI Security Project](https://genai.owasp.org)
- Repo: [module 01 AI security fundamentals](../../01-ai-security-fundamentals/README.md), [module 02 LLM security](../../02-llm-security/README.md), [module 03 RAG security](../../03-rag-security/README.md)
- Next: [Chapter 2: Understanding and Attacking LLMs](../ch2-understanding-and-attacking-llms/README.md)
