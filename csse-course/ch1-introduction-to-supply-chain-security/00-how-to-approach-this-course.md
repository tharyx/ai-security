# 00. How to approach this course (and the certification)

> **Chapter 1 · Time:** 45 minutes · **You will:** set up a study routine, know what the exam style looks like, and prepare your lab environment and support channel.
> **Unofficial companion.** Your course portal, videos, lab and support team are the primary source. This page is generic study advice; verify exam rules on the provider's own page.

## 1. Why this matters

Supply chain security is a wide subject: source control, CI/CD, packages, containers, Kubernetes and cloud. Learners who only watch videos remember the incident names and forget how the controls work. The course is practical, so study in a practical way.

## 2. Understand it

### 2.1 Course introduction: about the course, syllabus, and how to approach it

- The course has **7 chapters**. Chapter 1 gives the map. Chapters 2 to 5 attack each layer (code and application, containers, Kubernetes, cloud). Chapter 6 teaches the common defenses. Chapter 7 shows how to run a supply chain security program.
- The syllabus is partly from 2021 to 2022. Some tool names are old. Each chapter README here has an "Outdated in the syllabus → current" box. Learn the **syllabus term** (it may appear in the exam) **and** the current term (it is what an employer expects).
- Learn each topic in three passes: **read** (what is it), **break** (how is it attacked), **fix** (which control stops it, and which control only helps a little).

### 2.2 About certification and how to approach it

- Expect a **practical, hands-on style** exam in a browser lab, not only multiple choice (verify the exam format, duration and pass mark in your course portal; they change).
- Keep notes in your own words, in a table: *attack, why it works, detection, prevention, tool*. You will use this table in the exam and in interviews.
- Practice the lab commands until you do not need to look them up. Time matters in a practical exam.
- Know the **reasoning**, not only the command. The exam often changes the target slightly. If you understand why a pipeline leaks a secret, you can find it in a new pipeline.
- Do the hands-on exercises twice: once with the course, once from memory.

### 2.3 Course lab environment

- The course gives a **browser-based lab** (a remote desktop with tools already installed, GitLab, registries and a cluster). You do not need to install much on your laptop.
- Learn to: open a terminal, copy and paste between your laptop and the lab, find the lab's GitLab address, reset a broken lab, and note when your lab time expires (verify the rules in your portal).
- Your laptop can run the **offline labs in this repo** (Python only). They teach the same ideas without Docker, Kubernetes or a cloud account. They are a twin, not a replacement, for the course lab.
- Never put real company secrets or data in a training lab.

### 2.4 Lifetime course support (Mattermost)

- The provider offers a support chat (Mattermost) for questions about the course and labs; the course describes it as lifetime support. Verify the terms in your portal.
- Ask good questions: say which lab and step, paste the **exact error text** (remove any token or password), say what you already tried. A good question gets a fast answer.
- Search the channel before you ask: your problem is probably known.
- Never paste real secrets in a chat, even in a course chat.

## 3. Defend it (study habits that work)

| Habit | Why |
|---|---|
| Study 45 to 60 minutes, then run a lab | Practice fixes memory |
| One "attack to control" table per chapter | Exam questions ask for both sides |
| Draw the supply chain from memory (see [lesson 01](01-supply-chain-overview-and-building-blocks.md)) | Places every later topic on a map |
| Say each Q&A answer aloud | Interviews are spoken |
| Keep a list of "outdated terms" | Shows you know the field is moving |

**What does NOT work on its own:** watching videos at double speed, copying lab commands without reading the output, memorising tool names without knowing what problem each solves.

## 4. Hands-on

1. Run all four Chapter 1 labs once: see the [chapter README](README.md#lab-index).
2. Write your 12-line study plan: which chapter on which week. The repo's [36-week plan](../../00-program/36-week-plan.md) shows how this track fits into the wider learning path.
3. Make an empty "attack to control" table in a note-taking app. Fill it with the eight building blocks from [lesson 01](01-supply-chain-overview-and-building-blocks.md).

## 5. Common mistakes

- Skipping chapter 1 because it looks like theory. The threat model here is the frame for the six chapters after it.
- Trusting old tool names. Check the box in each README.
- Running attack labs against anything but the lab or your own sandbox.

## 6. Interview and exam preparation

<details><summary><b>Q1. How do you plan the study time for a practical certification?</b></summary>
Split each topic into read, break and fix. Spend at least half the time in labs. Review notes weekly. Re-do labs from memory before the exam.
</details>

<details><summary><b>Q2. Why keep an "outdated vs current" list?</b></summary>
Courses lag behind tools. Naming the old term and the current replacement shows you can work with real, changing systems.
</details>

<details><summary><b>Q3. How do you ask for help in a support chat?</b></summary>
State the lab and step, paste the exact error with secrets removed, say what you tried and what you expected.
</details>

## 7. Checklist

- [ ] I can open the course lab and the support channel.
- [ ] I have a weekly plan and an "attack to control" table.
- [ ] I know the exam format from my own portal (not from this page).

## 8. References

- Your course portal and its syllabus, exam rules and lab guide (primary source).
- Repo: [AUTHORING-GUIDE](../../00-program/AUTHORING-GUIDE.md), [36-week plan](../../00-program/36-week-plan.md).
