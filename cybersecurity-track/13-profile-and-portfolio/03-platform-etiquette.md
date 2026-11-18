# 03. Platform Etiquette: Spoilers and Write-up Rules

> **Module:** 13 · Profile and Portfolio · **Read in:** week 1 · **Time:** 30 minutes
> **You will:** know what you can and cannot publish about TryHackMe and Hack The Box content, and how to write useful posts without breaking rules or ruining the learning for others.

## 1. Why it matters

Platforms depend on people solving problems by themselves. If answers are public, the value falls for everyone, and the platform may remove your content or your account. Employers also notice: sharing flags looks careless, while a thoughtful write-up shows professionalism.

> **Always read the current terms and community rules on each platform before publishing.** Rules change. This lesson gives safe defaults. When the rule is unclear, choose the stricter choice or ask the platform support.

## 2. Safe defaults

| Do | Do not |
|---|---|
| Write about **methods**, concepts, and what you learned | Post flags, passwords, final answers or full step-by-step solutions to **active** content |
| Publish write-ups only for content that the platform allows (for example retired content where the rules permit it) | Write up active machines, challenges, Sherlocks or exam content |
| Use your own words, your own screenshots, and your own timeline | Copy the platform's text, images or diagrams |
| Link to the platform and give credit to the author | Pretend someone else's work is yours |
| Blur or remove flags and any personal tokens from screenshots | Share VPN files, API keys, session cookies |
| Keep exam content private. Never discuss the questions of a certification exam | Share exam details, even "a little hint" |
| Share generic skills ("I learned to pivot on a user field in Splunk") | Share a full path through a room |

## 3. Platform notes

- **TryHackMe:** room writers publish their work for learners. Do not publish answers to room questions. A write-up that teaches the method, with answers removed, is the safest kind. Check THM's current rules and terms on write-ups.
- **Hack The Box:** HTB has stated rules that restrict public write-ups of active content, while retired content has different rules and official walkthroughs for subscribers. Academy module answers are not for public sharing. For Sherlocks and Labs, check the current community guidelines and terms before posting.
- **Certification exams (SAL1, SAL2, CDSA, Security+, SC-200, AWS):** all have agreements that forbid sharing exam questions. Share your study approach only.
- **Other people's work:** quote sparingly with credit. For this repo's own labs, you may share freely because they use synthetic data.

## 4. How to write a safe, useful post

1. State the **skill** (for example "reading CloudTrail"), not the room's answer.
2. Describe the **approach**: what you looked for first, which fields, which tool.
3. Show a **generalized example** with fake data. Better: reproduce the idea in your own repo lab with synthetic logs.
4. Share the **lesson** and one mistake you made.
5. Add a line: "This is based on public learning material. I do not share flags or solutions."

## 5. Three realistic scenarios

1. **You want to write up a Sherlock that is still active.** Do not publish. Keep private notes. Publish later only if the rules allow, or write a generic post about the skill with your own synthetic data.
2. **A friend asks for the flag.** Offer a hint about the method, not the answer.
3. **You find a platform bug.** Report it through the official channel. Do not post it publicly.

## 6. Common mistakes

- "It's only a small spoiler." Small spoilers add up.
- Screenshots showing flags or cookies.
- Leaving a public repo with copied solutions.
- Assuming old rules still apply.

## 7. Interview questions

<details><summary><b>Q1. How do you handle confidentiality when you write about your learning?</b></summary>
I share methods and lessons, never answers for active content, never exam questions, never employer data. I use synthetic data in my own labs.
</details>

<details><summary><b>Q2. A colleague posts company logs in a blog to show a detection. What do you say?</b></summary>
Remove them. Logs may contain personal data and internal details. Rebuild the example with synthetic data and get approval if company knowledge is involved.
</details>

<details><summary><b>Q3. Why do certification bodies forbid sharing exam content?</b></summary>
It protects the value and fairness of the certificate, and breaking the agreement can cancel your certification.
</details>

<details><summary><b>Q4. How do you credit others?</b></summary>
Link to the original source, name the author, quote only short parts, and say what you added.
</details>

<details><summary><b>Q5. What do you do if you are unsure what is allowed?</b></summary>
Read the platform terms and community rules. If still unclear, do not publish, or ask support.
</details>

## 8. Checklist

- [ ] I read the current rules of each platform I use.
- [ ] My posts contain no flags, passwords or exam questions.
- [ ] Screenshots are checked before posting.
- [ ] I use synthetic data from my own labs for examples.

## 9. References

- TryHackMe terms and community rules: https://tryhackme.com/
- Hack The Box terms, rules and community guidelines: https://www.hackthebox.com/
- Certification candidate agreements (CompTIA, ISC2, Microsoft, AWS, HTB, THM): read the one for your exam.
