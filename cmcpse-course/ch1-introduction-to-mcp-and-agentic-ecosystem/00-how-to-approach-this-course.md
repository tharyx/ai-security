# 00: How to Approach This Course (and Use This Repo With It)

> **Chapter:** 1 · Introduction to MCP and Agentic Ecosystem · **Time:** ~45 minutes to read, then use as a reference all through the course
> **You will:** have a study routine that combines the paid course with this repository, know how to prepare for the certification, know when to use the course's browser-based lab and when to use this repo, and know how to ask good questions on the course support channel.

This note covers four syllabus lines: *About the course, syllabus, and how to approach it*, *About the CMCPSE Certification and how to approach it*, *Course Lab Environment*, and *Lifetime course support (Mattermost)*. It is deliberately generic. This companion folder is not the course and does not know the course's exam format, number of questions, passing score or lab tasks. For those, trust only the course's own pages. Anything below about the exam is general good practice, not inside information.

---

## 1. Two sources, one skill

| Source | What it gives you | How to use it |
|---|---|---|
| The paid course (videos, slides, browser lab) | The official syllabus, the course's own lab tasks, the exam | Follow it in order. It defines what you are tested on. |
| This repo (`cmcpse-course/`) | Plain-English notes, offline labs with tests, links to deeper repo modules | Use it to understand, repeat and extend. Nothing here replaces the course. |

A good loop for every topic: **watch or read the course section, read the matching note here, run the matching offline lab, then redo the course lab from memory.** If you can redo the course lab without looking, you understand it.

Every chapter README starts with a coverage table. Each line of the syllabus points to the note and the lab that cover it, so you can tick lines off as you go.

## 2. About the course and its syllabus

The course is called "Certified MCP Security Expert" (CMCPSE) in this repo. It has six chapters:

1. Introduction to MCP and the agentic ecosystem (this chapter).
2. Understanding and attacking MCP servers.
3. Threat modeling MCP architectures.
4. Defending and hardening MCP servers.
5. DevSecOps for MCP security.
6. Supply chain security and governance of MCP.

The story is simple: **learn what MCP is, break it, model the risk, fix it, automate the fixes, and govern it.** Chapter 1 gives you the vocabulary. If a word in Chapter 2 is unclear, come back here.

How to approach it:

- **Keep a one-page cheat sheet** with the three primitives, the three transports, the lifecycle steps and the OWASP MCP Top 10 ids. Add to it every chapter.
- **Do the hands-on parts.** MCP security is learned by sending a message and reading the reply, not by memorizing names.
- **Always ask two questions** of any MCP feature: *who controls it* (model, application or user) and *who must be trusted* (host, server, network).
- **Write in your own words.** Short notes you wrote yourself are worth more than long notes you copied.

## 3. About the certification (generic advice)

Check the course page for the exam format, duration, passing mark, retake rules and whether the exam includes a practical lab. Do not guess. Then prepare in a way that works for most security certifications:

- **Map every syllabus line to a skill you can show.** For each line ask: can I explain it in two sentences, draw it, and demonstrate it?
- **Practice the vocabulary.** Terms like *host*, *client*, *server*, *capability*, *transport*, *rug pull* and *confused deputy* must be exact.
- **If there is a practical part, practice under a clock.** Use the labs here with a timer.
- **Use the Q&A sections** at the end of every chapter README to test yourself out loud.
- **Know the sources of truth.** The MCP specification and the OWASP lists change. When a name or number matters, check the source (links in the README) and say "as of the date I checked".
- **Do not memorize one version only.** Know the idea (for example "tools are model-controlled") and the current names.

## 4. The browser-based lab vs this repo

| | Course browser lab | This repo |
|---|---|---|
| Where it runs | In your browser, on the course's servers | On your own laptop |
| What it is for | The official tasks, with the exact environment the exam and videos expect | Safe repetition, understanding the code, extending it |
| Setup | None. Log in and go. | Python virtual environment, `pip install -e .` (see the root README) |
| Network | The course decides | Offline. Labs use fake services, canary values and reserved `.example` domains |
| Tools | Real MCP SDKs, real hosts, real scanners | Pure-Python twins that show the same ideas, plus optional real-SDK scripts in [`real-sdk/`](real-sdk/) |
| Persistence | The course decides (it may reset) | Yours. Commit your notes and changes. |
| Risk | Contained by the course | Contained by design: nothing leaves your machine |

Use the browser lab **first** for each exercise, because it matches what you will be assessed on. Use this repo **afterwards** to see the pieces: the offline server is about 150 lines, so you can read all of it. When the two disagree, the course environment wins for the course, and the official MCP specification wins for the protocol.

A practical tip for the browser lab: copy every command you run into your own notes, with one line saying what it did. Lab sessions can end, and your notes are what you can repeat offline.

**Safety rules for every lab, here or in the course:**

- Only attack systems the course or you own and have set up for this purpose.
- Never put real credentials, real customer data or real tokens in a lab. Use dummy values.
- Never point a lab tool at a public MCP server you do not own.
- Treat any server you did not write as untrusted code. Run unknown servers in a container or VM.

## 5. Course support on Mattermost: how to ask good questions

The course offers lifetime support through a Mattermost chat. Use it. A good question gets a fast and useful answer, and writing it often solves the problem anyway. Before posting:

1. **Search the channel first.** Many questions were asked before.
2. **Name the exercise.** "Chapter 2, lab on the file server" is better than "the lab does not work".
3. **Say what you expected and what happened.** Paste the exact error text, not a screenshot of it when text will do.
4. **Share what you tried.** Two or three steps. This shows effort and removes obvious answers.
5. **Give your environment.** Browser lab or local, operating system, Python and package versions (`python --version`, `pip show mcp`).
6. **Make it minimal.** Can you reproduce it with five lines?
7. **Remove secrets** before pasting logs: tokens, keys, cookies, internal host names. (Lab 03 shows how a proxy can redact them for you.)
8. **Ask about concepts, not answers.** For graded or exam-like material, ask for hints or for the reasoning, and respect the course rules.
9. **Close the loop.** If you solve it, post the fix. The next learner will find it.

Example of a poor question: *"MCP server not working please help."*

Example of a good one:

> Chapter 1, "Connect to a local MCP server". Expected `tools/list` to return 2 tools. I get `-32600 Server not initialized`. I sent `initialize` then `tools/list` in the same terminal. I did not send `notifications/initialized`. Python 3.12, local environment, no secrets in the log. Do I need that notification before `tools/list`?

That question can be answered in one line, and the asker learns the lifecycle.

## 6. A study plan for this chapter

| Day | Do |
|---|---|
| 1 | Read [01 What is MCP](01-what-is-mcp.md) and [02 Architecture](02-mcp-architecture-deep-dive.md). Draw the host, client and server picture from memory. |
| 2 | Read [03 Agentic ecosystem](03-agentic-ecosystem.md) and [04 Security first look](04-mcp-security-first-look.md). Do the course lab. |
| 3 | Run labs 01 and 02 here. Break the server on purpose (bad JSON, wrong version). |
| 4 | Run labs 03 and 04. Optional: [`real-sdk/`](real-sdk/) and MCP Inspector. |
| 5 | Answer the 15 questions in the README without looking. Fix gaps. |

## 7. References

- MCP specification: <https://modelcontextprotocol.io/specification> (verify the current revision).
- Repo setup and conventions: the root `README.md` and [`00-program/AUTHORING-GUIDE.md`](../../00-program/AUTHORING-GUIDE.md).
- The same kind of note for the previous course: [CAISP chapter 1, lesson 00](../../caisp-course/ch1-introduction-to-ai-security/00-how-to-approach-this-course.md).
