# 04. Blogging and Research

> **Module:** 13 · Profile and Portfolio · **Start:** week 2 · **Time:** about 1.5 hours per week
> **You will:** choose topics from your labs, follow a simple writing workflow, publish in the right place, build a research habit, and follow a 12-week blog calendar tied to the track.
> **Maps to:** All modules (each post comes from one lab or lesson)

## 1. Why it matters

Writing forces you to understand. A short post about a lab you built is proof of skill, it helps other beginners, and it gives you stories for interviews. English is not your first language: that is fine. Short, clear sentences are good technical writing. Use a grammar checker and keep your own voice.

## 2. Picking topics from the labs

Good topic = one lab + one lesson + one personal angle.

| Source | Topic idea |
|---|---|
| Module 10 lab | "Five CloudTrail detections in about 150 lines of Python" |
| Module 11 lab | "Oracle audit records in a SIEM: five detections a DBA can write" |
| Any lesson | "X for DBAs": translate a concept using what you know |
| A mistake you made | "What I got wrong about ..." |
| A room or Sherlock (rules allowing) | The skill learned, not the answer |

Test: can you finish it in 600 to 1000 words and show one real output, table or diagram?

## 3. Writing workflow (about 90 minutes)

1. **Question (5 min):** the one thing the reader will learn. Write it as a title.
2. **Outline (10 min):** Problem, what I tried, what I found, what to do, one takeaway.
3. **Draft fast (40 min):** short sentences, no editing yet. Paste real output from your lab.
4. **Edit (20 min):** cut a third. Define each term the first time. Check facts and commands.
5. **Safety check (5 min):** no secrets, no employer data, no active-platform answers (see [etiquette](03-platform-etiquette.md)).
6. **Publish (10 min):** title, tags, link to the repo, one image.

Use the [blog post template](templates/blog-post-template.md).

## 4. Where to publish

| Place | Good for | Notes |
|---|---|---|
| Personal blog or **GitHub Pages** | Your home base, searchable, you own it | Free with a repo; markdown works; use it as the main place |
| **Medium** | Reach, simple editor | Platform rules and paywalls change; link back to your own copy |
| **LinkedIn** (post or article) | Recruiters and peers see it | Short post with a link beats long text; use the [LinkedIn template](templates/linkedin-post-template.md) |
| **GitHub** README or `docs/` | Technical depth with code | Good for lab explanations |

Simple plan: write once in markdown, publish on GitHub Pages (or your blog), post a short LinkedIn summary with the link, optionally copy to Medium later.

## 5. Research habits (30 minutes per week)

| Habit | How | Output |
|---|---|---|
| Read one CVE | Pick a CVE from the CISA Known Exploited Vulnerabilities catalog or a vendor advisory. Ask: what is affected, how is it exploited, how would I detect it, what do I patch? | One note in [trackers/research-notes.md](trackers/research-notes.md) |
| Read one vendor report | Cloud provider, EDR vendor, or incident response report. Extract: attacker steps, ATT&CK techniques, detections | 5-line summary |
| Follow ATT&CK updates | Read the release notes of new versions; look at techniques for cloud and identity | One technique you map to a lab rule |
| Check vendor docs changes | Cloud and Oracle release notes, security bulletins | A "what changed" line |
| Keep a source list | Add trusted blogs and advisories to an RSS reader | Weekly 20-minute scan |

Source quality: prefer primary sources (vendor advisories, NIST, CISA, MITRE). For news or social media, find the primary source before you repeat a claim. Never state a CVE number, date or number of victims you did not verify.

## 6. The 12-week blog topic calendar

Post one piece per week after you finish the matching track work. If you are behind, shift the calendar. A late post is better than none.

| Week | Track module | Topic | Format |
|---|---|---|---|
| 1 | 00 Career plan | "From Oracle DBA to Cloud Security and SOC: my 36-week plan" | Short intro post |
| 2 | 11 Database (concept) | "What an Oracle DBA already knows about security" (a table of DBA habits and security names) | List post |
| 3 | 01 IT fundamentals | "Five Windows and Linux logs a SOC analyst reads first" | How-to |
| 4 | 02 Networking | "My first TShark filters: reading a capture like a listener log" | Walkthrough with a synthetic capture |
| 5 | 03 Security foundations | "CIA triad with database examples" | Explainer |
| 6 | 05 SOC fundamentals | "My alert triage checklist for a suspicious login" | Checklist |
| 7 | 06 SIEM | "From AWR baselines to SIEM baselines" | Analogy post |
| 8 | 10 Cloud | "Five CloudTrail detections in Python, with tests" | Lab write-up |
| 9 | 10 Cloud | "iam:PassRole explained for DBAs" | Explainer |
| 10 | 11 Database | "Oracle unified audit to SIEM: five detections" | Lab write-up |
| 11 | 08 Vulnerability mgmt | "Prioritizing patches: CVSS, EPSS and the KEV list" | Explainer |
| 12 | 09 Pentesting basics or 12 Soft skills | "SQL injection in a safe in-memory lab, and the fix with bind variables" or "Three interview stories using STAR" | Lab write-up or story |

After week 12: one post per two weeks, plus one deep investigation per quarter.

## 7. Three realistic scenarios

1. **You have no time.** Write a 300-word "note" post: one chart or output and one lesson. Small posts count.
2. **A reader points out an error.** Thank them, fix the post, add an "Updated" line. This shows maturity.
3. **A post gets no views.** Normal. Keep the habit. Share in one more place and link it in your LinkedIn Featured section.

## 8. Common mistakes

- Waiting for a perfect post.
- Copying text from vendor pages.
- Posting private or company data.
- Claiming expertise you do not have: say "learning" and be specific.
- Not linking the code.

## 9. Interview questions

<details><summary><b>Q1. How do you stay up to date?</b></summary>
Weekly: one CVE or advisory, one vendor report, ATT&CK release notes, plus cloud and Oracle release notes. I keep short notes and test one idea in a lab.
</details>

<details><summary><b>Q2. Tell me about something you built or wrote.</b></summary>
Use the lab and post: problem, approach, result with a number (for example "five detections, 41 tests, zero false positives on a benign admin set"), and what you would improve.
</details>

<details><summary><b>Q3. How do you check a claim in a news article about a breach?</b></summary>
Find the primary source (advisory, vendor report, regulator filing), check dates and technical details, and avoid repeating numbers I cannot verify.
</details>

<details><summary><b>Q4. How do you explain a technical topic to a manager?</b></summary>
Start with the business impact, then the risk in simple words, then one action and its cost. Keep the technical details in a short appendix.
</details>

<details><summary><b>Q5. Describe your writing process.</b></summary>
One question per post, an outline, a fast draft, edit and cut, safety check, publish and link the code.
</details>

## 10. Checklist

- [ ] Blog home chosen and first post published.
- [ ] Calendar copied into my tracker.
- [ ] Weekly research note done.
- [ ] Every post passes the safety check.

## 11. References

- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST National Vulnerability Database: https://nvd.nist.gov/
- MITRE ATT&CK updates: https://attack.mitre.org/resources/updates/
- GitHub Pages docs: https://docs.github.com/pages
