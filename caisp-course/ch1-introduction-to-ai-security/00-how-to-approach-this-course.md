# 00: How to Approach This Course (and Use This Repo With It)

> **Chapter:** 1 · Introduction to AI Security · **Time:** ~1 hour to read, then use as a reference all through the course
> **You will:** have a study routine that combines the paid course with this repository, know how to prepare for the certification exam, know when to use the course lab environment and when to use this repo, and know how to ask good questions in the support community.

This note covers four syllabus lines: *Course Introduction (about the course, syllabus, how to approach it)*, *About Certification and how to approach it*, *Course Lab Environment*, and *Lifetime course support (Mattermost)*. It is deliberately generic. Details that belong to the course provider (exam format, passing score, lab URLs, support rules) change over time, so **always take them from the course portal and the provider's official pages, not from this repo**.

---

## 1. The big picture: two sources, one skill

| Source | What it gives you | How to use it |
|---|---|---|
| **The course** (videos, slides, guided labs, portal) | The official syllabus, the provider's way of explaining things, a ready-made lab environment, and the exam | Follow it in order. It defines what the exam expects. |
| **This repo** (`caisp-course/` plus modules 01 to 10) | Plain-English explanations, offline labs with tests, interview questions, deeper coverage of some topics | Use it **after** each course section to understand, practise and revise. |

The course tells you *what* to know. This repo helps you *prove you know it* by running code and answering questions without looking.

## 2. A weekly study routine

A simple loop for every course section:

1. **Preview (10 minutes).** Read the chapter `README.md` here: the coverage table and the exam tips.
2. **Watch or read the course section.** Take short notes in your own words. Do not copy slides.
3. **Read the matching lesson here** (the table in the chapter README tells you which one).
4. **Run the lab.** First in the course lab environment (it matches the exam material). Then the offline twin here: `python -m pytest <lab folder>` and `python <lab folder>/demo.py`.
5. **Break it.** Each lab has a "break it yourself" step. Predict the result before running. A wrong prediction is the best learning moment.
6. **Recall (15 minutes, next day).** Close everything and answer the chapter's Q&A out loud. Only then open the answers.
7. **Write one page** in your journal: three things learned, one thing still confusing, one question to ask the community.

Keep a small glossary file of terms you meet. Re-read it weekly.

> **For a learner with a DBA/DevOps background:** map every new idea to something you know. A *training dataset* is like a production data load that nobody reviewed. A *model file* is like a binary artifact from a registry. A *prompt* is like user input that is concatenated into a SQL string. This habit makes AI security feel familiar.

## 3. Using the course lab environment versus this repo

| | Course lab environment | This repo's offline labs |
|---|---|---|
| **Purpose** | Hands-on with real tools and real models, as the exam expects | Understand the *idea* with tiny deterministic examples and tests |
| **Needs** | Internet, the provider's platform, often a GPU or hosted notebooks | A laptop with Python. No GPU, no API key, no big downloads |
| **Behaviour** | Real models are random: the same attack may work only sometimes | The mock model is deterministic, so a test can prove an attack and its fix |
| **When to use** | During the course session and for exam-style practice | Before the session (to prepare), after it (to revise), and when the platform is slow, unavailable or expired |
| **Risk** | Shared or time-limited environment | Everything is local and harmless (canaries, `*.example` domains) |

Rules of thumb:

- Do the **course lab first** when the course says so, because the exam may use the same tools.
- Use the **repo lab second** to see *why* it worked. Many chapters here have an "offline twin" of each heavy lab (for example a toy trigger-and-backdoor model instead of a real BackdoorBox run).
- For labs that need a GPU, the repo also provides a Colab notebook. Treat those as optional extras, and read their warning: they were **not executed by the repo author** and library versions may need updating.
- Never run attack tools against systems you do not own or have written permission to test. Use only the lab targets.

### Setting up the repo labs

```bash
# from the repository root
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"      # Windows; on Linux/macOS use .venv/bin/python
.venv/Scripts/python -m pytest caisp-course/ch1-introduction-to-ai-security
```

All labs use `aisec_lab.get_llm()`, which returns a deterministic mock model by default. To try a real local model, install [Ollama](https://ollama.com), pull a small model and set `AISEC_LLM_BACKEND=ollama`.

## 4. Approaching the certification

Everything about the exam itself (number of questions, practical or multiple choice, duration, passing score, retake policy, whether you get a lab or a report task) **must be read from the course portal and the certification page**. This repo does not know them and does not guess.

What you can do in any case:

- **Get the official exam outline and map it** to this repo's chapter tables. For each line, mark: *can explain*, *can demonstrate*, *can defend*.
- **Practise both modes.** Be ready to explain a concept in two sentences *and* to do it in a terminal. If the exam has a practical part, speed and calm matter: repeat the course labs until the commands feel natural.
- **Practise the language of the syllabus.** The course uses the OWASP Top 10 for LLM Applications **2023 (v1.1)** names (for example *Insecure Output Handling*, *Model Denial of Service*). Newer lists use different names. Learn both. Chapter 3 has a comparison note.
- **Learn the "why" behind each control.** Exams reward "this control works because it is enforced in code, not in the prompt", more than a list of names.
- **Time-box.** Plan the last two weeks for revision only: re-run labs, redo Q&As, re-read your one-page notes.
- **Rest before the exam.** Check your technical setup (browser, network, ID, lab access) early, as the provider tells you to.
- **Keep integrity.** Do not share exam questions and do not use unauthorised help. This protects the value of your certificate.

## 5. Lifetime support and community (Mattermost or similar)

Course providers often give a chat community where you can ask the instructors and other learners. (Check the portal for how to join and what the support promises.) Good questions get fast answers. Use this template:

```text
Title: [Chapter 2, Lab 5] Web scraper returns empty text on step 3

Goal: what I was trying to do, in one sentence.
Environment: course lab / my laptop; OS; Python version; tool versions.
What I did: the exact commands or steps (copy and paste, not retyped).
What I expected vs what happened: expected output, then the actual error text (full, not a screenshot of part of it).
What I already tried: two or three things, and what each showed.
```

Good habits:

- **Search first.** Many questions already have answers.
- **One question per post.** Include the exact error text and the step number.
- **Remove secrets** (API keys, tokens, personal data) before pasting logs.
- **Share what worked** when you solve it. Teaching others is the best revision.
- **Ask about concepts too**, not only errors: "Why does a rate limit help with Model DoS but not with prompt injection?"
- Be polite and patient; instructors and volunteers are people in different time zones.

## 6. Interview and exam Q&A for this note

<details><summary><b>Q1. How should I split my time between the course and the repo?</b></summary>

Follow the course for content and exam alignment. Use the repo for understanding and practice after each section. A good split is about 60% course and course labs, 40% repo labs, Q&A and notes.
</details>

<details><summary><b>Q2. Why run the same lab twice (course environment, then offline twin)?</b></summary>

The course lab shows the real tool. The offline twin shows the mechanism with a deterministic model and tests, so you can see exactly why the attack works and which control stops it.
</details>

<details><summary><b>Q3. What if I do not know the exam format?</b></summary>

Read the course portal and the official certification page. Do not rely on forum rumours. Prepare for both explanation and hands-on tasks until you know better.
</details>

<details><summary><b>Q4. What makes a good support question?</b></summary>

A clear goal, environment details, exact steps, exact error text, expected versus actual result, and what you already tried. No secrets in the paste.
</details>

## 7. Checklist

- [ ] I found the exam outline and exam rules on the course portal.
- [ ] I can run `python -m pytest caisp-course/ch1-introduction-to-ai-security` on my laptop.
- [ ] I have a weekly slot for preview, course, lesson, lab and recall.
- [ ] I know how to join the support community and I have a question template.
- [ ] I have a journal page for chapter 1.

## 8. References

- Your course portal (exam rules, lab access, support policy): the source of truth.
- [Authoring guide](../../00-program/AUTHORING-GUIDE.md): how lessons in this repo are written.
- [36-week plan](../../00-program/36-week-plan.md): the wider learning plan, if you follow it.
