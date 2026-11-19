# 00: How to Approach This Course (and Use This Repo With It)

> **Chapter:** 1 · Agents, Harnesses and the Agentic Ecosystem · **Time:** ~45 minutes to read, then use as a reference all through the course
> **You will:** have a study routine that combines the paid course with this repository, know how to prepare for the certification, know when to use the course's browser lab and when to use this repo, and know how to ask for help well.

This note covers four syllabus lines: *About the course, syllabus, and how to approach it*, *About the CAASE Certification and how to approach it*, *Course Lab Environment*, and *Lifetime course support 24 x 7*. It is deliberately generic. This companion folder is not the course. It does not know the exam format, number of questions, passing score or lab tasks. For those, trust only the course's own pages. Anything about the exam below is general good practice, not inside information.

---

## 1. Two sources, one skill

| Source | What it gives you | How to use it |
|---|---|---|
| The paid course (videos, slides, browser lab) | The official syllabus, the course's own lab tasks, the exam | Follow it in order. It defines what you are tested on. |
| This repo (`caase-course/`) | Plain-English notes, offline labs with tests, links to deeper repo modules | Use it to understand, repeat and extend. It does not replace the course. |

A good loop for every topic: **watch or read the course section, read the matching note here, run the matching offline lab, then redo the course lab from memory.** If you can redo the course lab without looking, you understand it.

Every chapter README starts with a coverage table. Each syllabus line points to a note and a lab, so you can tick lines off as you go.

## 2. About the course and its syllabus

The course is called "CAASE" in this repo, an AI agent security expert certification. It appears to come from the same provider as the CAISP and CMCPSE courses that this repo already covers ([CAISP](../../caisp-course/README.md), [CMCPSE](../../cmcpse-course/README.md)). That is an assumption: check the course page. It has seven chapters:

1. Agents, harnesses and the agentic ecosystem (this chapter).
2. Agent reasoning, goals and prompt boundaries.
3. Agent memory, context and tool use.
4. Computer use, browser and coding agents.
5. Multi-agent systems and agent identity.
6. Operationalizing agentic AI security.
7. Threat modeling agents and communication protocols.

The story: **learn what an agent and its harness are, see the attack surface, attack and defend each layer (reasoning, memory, tools, computer use, multi-agent), then operate and threat-model it.**

> **The syllabus may contain old information.** AI agent tools change every few months. Where the syllabus wording is outdated, each chapter has an "Outdated in the syllabus → current" box. Learn the course's words for the exam, and the current facts for your job. When you are unsure, check the source and write "as of the date I checked".

How to approach it:

- **Keep a one-page cheat sheet:** the agent loop, the harness parts, OWASP ASI01 to ASI10, the 14 ATLAS tactics, and the sizing formula. Add to it every chapter.
- **Do the hands-on parts.** Agent security is learned by watching an injected note make a harness send an email, then adding the guard and watching it stop.
- **Ask two questions of every feature:** *who decides this action (model, harness, human)?* and *what is the worst thing it can do if the model is fully fooled?*
- **Write in your own words.** Short notes you wrote yourself beat long notes you copied.

## 3. About the certification (generic advice)

Check the course page for the exam format, duration, passing mark, retake rules and whether there is a practical lab. Do not guess. Then prepare in a way that works for most security certifications:

- **Map every syllabus line to a skill you can show.** For each line: can I explain it in two sentences, draw it, and demonstrate it?
- **Learn exact vocabulary.** Harness, runtime, planner, executor, trust boundary, blast radius, goal hijack, confused deputy.
- **Practice under a clock** if there is a practical part. Use the offline labs with a timer.
- **Use the Q&A sections** at the end of each chapter README, out loud.
- **Know the sources of truth** (OWASP, MITRE ATLAS, NIST, vendor docs) and say "as of the date I checked" for numbers.
- **Do not memorize one version only.** Know the idea and the current names.

## 4. The browser-based lab vs this repo

| | Course browser lab | This repo |
|---|---|---|
| Where it runs | In your browser, on the course's servers | On your laptop |
| Purpose | The official tasks and the exact environment the exam expects | Safe repetition, reading the code, extending it |
| Setup | None | Python virtual environment, `pip install -e .` (see the root README) |
| Models | Whatever the course provides (local open-weight and routed cloud models) | A deterministic mock model by default; optional small Ollama model |
| Network | The course decides | Offline. Labs use fakes, canaries and `.example` domains |
| Tools | Real harnesses, UIs and proxies (LibreChat, Hermes and similar) | Pure-Python twins plus hedged guides in [`real-tools/`](real-tools/) |
| Risk | Contained by the course | Contained by design |

Use the browser lab **first** for each exercise, because it matches the assessment. Use this repo **afterwards** to see the pieces. When the two disagree, the course environment wins for the course, and the vendor documentation wins for the tool.

**Your laptop (16 GB RAM, no GPU, little disk space):** do not try to run large models locally. Small models (1B to 4B, 4-bit) work on CPU. Use the course browser lab or a cloud route for anything bigger, and the [sizing calculator](labs/model-sizing-calculator/) to check before you download.

**Safety rules for every lab, here or in the course:**

- Attack only systems the course or you own and set up for this purpose.
- Never put real credentials, real customer data or real tokens in a lab. Use values marked FAKE.
- Never point a lab tool at a real exposed agent or at a public server you do not own.
- Treat any skill, plugin or MCP server you did not write as untrusted code. Run it in a container or VM.

## 5. Lifetime course support (24 x 7): how to ask good questions

The course offers lifetime support around the clock. Use it, and make your question easy to answer:

1. **Search first.** Many questions were asked before.
2. **Name the exercise:** "Chapter 1, minimal harness exercise, step 3", not "the lab does not work".
3. **Say what you expected and what happened.** Paste the exact error text.
4. **Share what you tried** (two or three steps).
5. **Give your environment:** browser lab or local, operating system, model name and size, versions (`python --version`, `ollama --version`).
6. **Make it minimal.** Can you reproduce it in ten lines?
7. **Remove secrets** before pasting logs: API keys, tokens, cookies, internal host names.
8. **Ask for hints for graded material,** and respect the course rules.
9. **Close the loop.** Post the fix when you find it.

Example of a poor question: *"Agent does not call the tool, help."*

A good one:

> Chapter 1, "Minimal agent harness". The model replies with prose around the JSON, and my parser returns no tool call. Model: a 3B model, 4-bit, on CPU. Expected `{"tool": "add", "args": {"a": 2, "b": 40}}`. I tried temperature 0 and a stricter system prompt. Should the harness extract the first JSON object from the reply, or should I use constrained output?

That question teaches the asker about parsing and schema enforcement, and gets a one-line answer.

## 6. A study plan for this chapter

| Day | Do |
|---|---|
| 1 | Read [01 Agent vs LLM call](01-agent-vs-llm-call.md). Run [minimal-agent-harness](labs/minimal-agent-harness/). |
| 2 | Read [02 Anatomy of a harness](02-anatomy-of-an-agent-harness.md). Read the [real-tools](real-tools/) guides (do not install yet). |
| 3 | Read [03 Attack surface](03-agentic-attack-surface.md) and [04 Frameworks](04-threat-modeling-and-risk-frameworks.md). Run [atlas-threat-model-agent](labs/atlas-threat-model-agent/). |
| 4 | Read [05 Free and open toolchain](05-free-open-agentic-toolchain.md). Run [model-sizing-calculator](labs/model-sizing-calculator/), [routing-proxy](labs/routing-proxy/) and [tool-calling-determinism](labs/tool-calling-determinism/). |
| 5 | Redo the course lab from memory. Answer the 15 questions in the README. |

## 7. References

- Repo setup and conventions: the root `README.md` and [`00-program/AUTHORING-GUIDE.md`](../../00-program/AUTHORING-GUIDE.md).
- The same kind of note for the previous courses: [CAISP chapter 1, lesson 00](../../caisp-course/ch1-introduction-to-ai-security/00-how-to-approach-this-course.md) and [CMCPSE chapter 1, lesson 00](../../cmcpse-course/ch1-introduction-to-mcp-and-agentic-ecosystem/00-how-to-approach-this-course.md).
