# Lesson 01: How to Approach This Merged Course and Its Exams

**Syllabus items covered:** [CSC 0] Course Introduction (about the course, syllabus, and how to approach it), About Certification and how to approach it, Lab Environment, Course support (Mattermost).

**Time:** 45 minutes. **Safety:** planning only. Only test systems you own or have written permission to test.

> **DBA analogy.** Before a big migration you read the runbook end to end, set up a rehearsal environment, and plan checkpoints. Do the same here: read the map, set up the labs once, and plan your exam rehearsals.

## 1. About this merged course

You are taking three overlapping courses (they appear to come from Practical DevSecOps): **Security Champion** ([CSC n]), **Threat Modeling** ([CTMP n]) and **API Security** ([CASP n]). This folder merges them into **17 chapters**. Every source syllabus line appears in exactly one chapter's "Syllabus coverage" table, tagged with its course and chapter, so you can always find where a topic lives.

| Block | Chapters | What you get |
|---|---|---|
| AppSec foundations | 01 to 02 | Champions, HTTP, OWASP Top 10, secure code review, ASVS |
| Risk and threat modeling | 03 to 07 | Risk management, STRIDE and friends, threat modeling as code, tools, secure design |
| API security | 08 to 15 | API basics, recon, authentication, authorization, injection, OWASP API Top 10, defenses |
| DevSecOps and people | 16 to 17 | Pipelines, IaC, agile communication and soft skills |

**How to study each chapter:**

1. Read the chapter README: coverage table, "Outdated in the syllabus", learning order.
2. Read the lessons in order. Each one has a scenario; say aloud what you would do.
3. Run each lab: `demo.py` first (see what happens), then the tests, then break the secure version on purpose and watch a test fail.
4. Answer the 15 questions at the end of the README without looking.
5. Repeat the course's own lab exercises in the course lab environment.

**Where the syllabus is old,** the chapter says so and gives the current fact (for example the OWASP Top 10 2021 list versus the 2025 list). Learn both: the exam follows the course material; your job follows the current standards.

## 2. The certification exams and how to approach them

Practical DevSecOps exams are, in general, **hands-on, practical and time-boxed**: you get a lab environment and tasks to complete, then often a report to write. Exact rules (duration, number of tasks, report format, pass mark, retakes, whether internet search is allowed) change, so **check your exam guide in the course portal**. Treat everything in this section as study advice, not exam rules.

**Before the exam**

- Do every course lab **twice**: once following the guide, once from memory with a timer.
- Keep a **personal cheat sheet** of commands and payloads you used (curl, Burp steps, sqlmap flags, jq filters, common headers). If notes are allowed, it saves time; if not, writing it still helps memory.
- Practise **writing findings**: title, affected endpoint, steps to reproduce, impact, evidence, fix. A finding nobody can reproduce scores poorly.
- Practise the boring parts: starting tools, configuring the browser proxy, installing a CA certificate, reading a long response.

**During the exam**

| Do | Avoid |
|---|---|
| Read all tasks first; do the quick ones first | Spending an hour on one stuck task |
| Take evidence (request, response, screenshot) as you go | Trying to remember steps afterwards |
| Confirm each finding twice (repeat the request) | Reporting a scanner result you did not verify |
| Stay inside the scope you were given | Touching hosts or accounts outside scope |
| Leave time for the report | Writing the report in the last 10 minutes |

**After the exam:** write down what was hard while you still remember it; it is your study list for the next certification.

## 3. Lab environment

There are two lab environments, and they do different jobs:

| | Course lab environment | This repo's labs |
|---|---|---|
| Where | Browser-based labs from the course portal (check your portal for access and time limits) | Your laptop, `D:\FreeLaProjects\ai-security` |
| Tools | Real tools: Burp Suite, ZAP, sqlmap, Docker, GitLab and so on | Python standard library, `pytest` |
| Targets | Deliberately vulnerable apps prepared by the course | Small in-process toy apps (no sockets, no internet) |
| Purpose | Practise the exam's exact skills | Understand **why** each attack works and **prove** the fix with a test |

Run every repo lab from the repository root with the project's virtual environment:

```text
.venv/Scripts/python appsec-course/01-security-champions-and-appsec-basics/labs/vulnerable-shop/demo.py
.venv/Scripts/python -m pytest appsec-course/01-security-champions-and-appsec-basics -q -p no:cacheprovider
```

**Lab rules that also apply at work:** only test systems you own or have written permission to test; never point a lab payload at a real site; never paste real secrets or customer data into a lab.

## 4. Course support

The course provides a chat community for questions (the syllabus names **Mattermost**). Check your course portal for how to join and what response times to expect. Good habits when you ask:

- Say which chapter and lab, what you ran, what you expected and what you saw (paste the exact error).
- Remove anything sensitive (tokens, real hostnames) before you paste.
- Search the channel first; most lab issues have been asked before.
- When you solve something, post the answer. Helping others is champion behaviour (lesson 02).

## 5. Scenario: planning a study week

Priya, a cloud security engineer with a DBA background, has 6 hours a week. Her plan for chapter 01:

| Day | Time | Task |
|---|---|---|
| Mon | 1 h | Lessons 01 and 02; write her own "why champions" pitch in five sentences |
| Wed | 1.5 h | Lesson 03 and the intercepting-proxy lab; repeat it in Burp in the course lab |
| Fri | 1.5 h | Lessons 05 and 06; vulnerable-shop lab; break one secure handler on purpose |
| Sat | 2 h | Course labs for SQLi, XSS, CSRF, SSRF with a timer; write two findings as if for the exam |

She ends the week by answering the 15 README questions. The two she gets wrong go on her cheat sheet.

## 6. Checklist

- [ ] I know which chapter each course's lines map to (see the course README).
- [ ] The repo labs run on my machine with `.venv/Scripts/python`.
- [ ] I have access to the course lab environment and the course chat community.
- [ ] I have read my exam guide and written down its rules (time, report, retakes).
- [ ] I have a finding template and a personal cheat sheet started.
