# Certified AI Security Professional: Course Companion

A study companion for the **Certified AI Security Professional** course, organized exactly like its 7-chapter syllabus.
For every syllabus line it either points you to the lesson that already covers it in this repo, or gives you a new lesson and lab here. **Nothing in the syllabus is skipped.** Check line by line in [SYLLABUS-MAP.md](SYLLABUS-MAP.md).

> This is an unofficial companion. Use your course's own videos, lab environment and support community as the primary source. Use this repo to understand topics more deeply, practice offline, and prepare for interviews.

## Chapters

| # | Chapter | What's new here | Key labs |
|---|---|---|---|
| 1 | [Introduction to AI Security](ch1-introduction-to-ai-security/) | AI history, types of AI, learning paradigms, NLP/CV, core components, CNNs | Learning-paradigm toys, CNN convolution, LLM chatbot |
| 2 | [Understanding and Attacking LLMs](ch2-understanding-and-attacking-llms/) | GPT vs BERT, use cases, **ATT&CK vs ATLAS: every tactic**, WormGPT/FraudGPT threat briefing | 10 course exercises + ATLAS mapping |
| 3 | [LLM Top 10 Vulnerabilities](ch3-llm-top-10-vulnerabilities/) | The course's OWASP **2023** list, mapped to 2025/2026; a lab for every risk | Prompt-injection levels, system vs user prompts, data extraction, hallucination |
| 4 | [AI Attacks and Defenses Using DevOps](ch4-ai-attacks-and-defenses-devops/) | Pipeline attacks, poisoned pipeline execution, Hugging Face / NotPetya / SAP AI Core cases, SCA/SAST/DAST, AI firewalls | Third-party vulns, AI code weaknesses, picklescan, agent scan, LLM Guard, PPE |
| 5 | [Threat Modeling AI Systems](ch5-threat-modeling-ai-systems/) | DFDs for LLM apps, STRIDE per element, AI threat libraries (BIML, MIT AI Risk Repository, AIID), risk rating | Threat-model an AI system |
| 6 | [Supply Chain Attacks in AI](ch6-supply-chain-attacks-in-ai/) | Slopsquatting, vetting, dependency confusion, SLSA, SCVS, SBOM/MLBOM, model signing | ROME, trojaned models/NNs, model code injection, signing |
| 7 | [Emerging Threats, Governance & Compliance](ch7-emerging-threats-governance-compliance/) | AI worms (Morris II), fine-tuning backdoors, NIST/ISO landscape, EU AI Act, **US legislation (2026)** | AI worm simulation, fine-tuning backdoor, working with and abusing agents |

**Important for the exam:** the course teaches the OWASP Top 10 for LLMs **2023 (v1.1)** names, such as "Insecure Plugin Design", "Overreliance" and "Model Theft". The rest of this repo uses the **2026** list. Learn both, using [the mapping](ch3-llm-top-10-vulnerabilities/owasp-llm-2023-vs-2026.md).

## How the labs work on your laptop

| Lab type | Where it runs | Needs |
|---|---|---|
| `labs/…` (offline twin) | Your laptop | Nothing extra: `python -m pytest caisp-course` |
| `notebooks/….ipynb` (real tools: transformers, TextAttack, BackdoorBox, ROME, Whisper, LLM Guard, picklescan, cosign) | **Google Colab** (free GPU) or your course lab environment | A browser |

Each notebook has an offline twin that teaches the same idea, so you can always practice even without a GPU. **The notebooks were not executed by the repo author**, so library versions may need small updates. Your course's lab environment is the main place for those tools.

> Your laptop has no GPU and little free space on D:, so don't `pip install torch` or `transformers` locally. Use Colab.

## Study loop per chapter

1. Watch the course chapter.
2. Open the chapter README here. Work down the coverage table, reading the linked lessons.
3. Run the offline labs, then the notebooks (Colab) or the course lab.
4. Answer the chapter's 15 exam-style questions without notes.
5. Write a short journal note and tick the chapter in [SYLLABUS-MAP.md](SYLLABUS-MAP.md).

## How this connects to the rest of the repo

Most deep material already lives in the AI roadmap modules. The chapters link to it instead of copying it:

| Course chapter | Repo modules it leans on |
|---|---|
| 1–2 | [01 fundamentals](../01-ai-security-fundamentals/), [03 RAG](../03-rag-security/) |
| 3 | [02 LLM security](../02-llm-security/), [04 MCP / tools](../04-mcp-security/), [05 agents](../05-agent-security/) |
| 4, 6 | [06 AI DevSecOps](../06-ai-devsecops/), [02 · model-threats](../02-llm-security/model-threats/) |
| 5 | [01 · threat modeling](../01-ai-security-fundamentals/03-ai-threat-modeling.md) |
| 7 | [05 agents](../05-agent-security/), [07 governance](../07-ai-governance/), [08 compliance](../08-ai-compliance/) |
