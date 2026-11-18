# 02. Hack The Box Plan

> **Module:** 13 · Profile and Portfolio · **Start:** week 8 · **Time:** 1 to 2 hours per week
> **You will:** use HTB Academy for the SOC Analyst path and the CDSA certification, practice with Sherlocks on HTB Labs, and understand how LetsDefend content is moving into HTB.
> **Maps to:** SOC analyst job skills · HTB Certified Defensive Security Analyst (CDSA)

## 1. Why it matters

TryHackMe is a gentle guided start. Hack The Box (HTB) goes deeper and is respected by employers for hands-on skill. For a blue-team (defense) career, two parts matter most: **Academy** (structured learning) and **Labs Sherlocks** (investigations that feel like real SOC cases).

## 2. The parts (verified, Nov 2026)

| Part | What it is | Use it for |
|---|---|---|
| **HTB Academy: SOC Analyst job-role path** | A structured sequence of modules for the SOC analyst role | Main study path. Leads to the CDSA exam |
| **HTB CDSA** | Certified Defensive Security Analyst, a practical certification connected to the SOC Analyst path | A goal for months 6 to 9. Check the official page for the format, price and path requirements |
| **HTB Labs: Sherlocks** | Defensive investigations: you get artifacts (logs, captures, files) and answer questions | Blue-team practice and portfolio write-ups |
| **LetsDefend content** | Blue-team training content that is moving into HTB | Check the HTB site for where the content lives now and what is included in your plan |

Module and Sherlock names change. Search by **topic** in the platform instead of copying names from blogs.

## 3. How to use Academy

1. Open the SOC Analyst path and read its module list and time estimate.
2. Match modules to the track: a log-analysis or SIEM module in track weeks 9 to 12; a Windows event log or Sysmon module with module 07; a web attack module with module 09; an incident handling module with the cloud IR lesson.
3. Do the module exercises yourself. Academy has its own rules about sharing answers (see [etiquette](03-platform-etiquette.md)).
4. Log each module in [trackers/htb-modules-and-sherlocks.md](trackers/htb-modules-and-sherlocks.md) with time and "lessons learned".
5. Review the CDSA exam page two months before you want to book it.

## 4. How to use Sherlocks

| Step | Action |
|---|---|
| Choose | Pick a Sherlock whose artifact type matches the module: cloud or identity logs for module 10, endpoint logs for 07, network captures for 02, ransomware or data theft for 11 |
| Read first | Scenario and questions. Decide what evidence you need |
| Work | Timeline in a text file. Note each artifact and what it proves |
| Check | Submit answers in the platform |
| Write | Only for **retired** content, in your own words, no flags. See etiquette |

Aim for: 1 Sherlock per 2 weeks at first.

## 5. Study schedule suggestion

| Weeks | Focus |
|---|---|
| 8 to 20 | Academy SOC Analyst path, first third of modules; Sherlocks easier ones |
| 21 to 32 | Academy second and third part; one write-up per month |
| 33+ | CDSA preparation: review weak topics, practice timed investigation |

## 6. Three realistic scenarios

1. **Module feels too long.** Break it into sections, set a timer, keep a short note after each section.
2. **Sherlock question has no clear answer.** Rebuild the timeline, search for the artifact field again, and read the artifact documentation. Record what you missed.
3. **Subscription cost vs value.** Choose the plan that unlocks what you will use in the next three months. Check the official pricing page, because plans change.

## 7. Common mistakes

- Starting the exam path before basics (SIEM, Windows logs, networking).
- Doing only offensive content.
- Copying tool output without writing a conclusion.
- Writing up active content.

## 8. Interview questions

<details><summary><b>Q1. What is the HTB SOC Analyst path and what did you gain?</b></summary>
It is a job-role path of defensive modules. State which modules you finished, and describe one skill you used in a real or lab case, such as building a timeline from logs.
</details>

<details><summary><b>Q2. What is a Sherlock?</b></summary>
A guided defensive investigation on HTB Labs where you analyze artifacts to answer questions about an incident.
</details>

<details><summary><b>Q3. How do you build an incident timeline?</b></summary>
Normalize timestamps to one timezone, list events from each source, order them, mark the first and last attacker activity, mark gaps, and tie each event to evidence.
</details>

<details><summary><b>Q4. Why choose CDSA?</b></summary>
It is a practical defensive certification tied to a SOC role path. It tests investigation skill rather than only memory. Check the exam details on the official site.
</details>

<details><summary><b>Q5. How do you choose what to study first?</b></summary>
By the job: cloud logs and SIEM first, endpoint and incident handling second, deeper hunting later. Use the track module of the week.
</details>

## 9. Checklist

- [ ] Academy account ready and path opened.
- [ ] First module logged in the tracker.
- [ ] One Sherlock chosen to match this month's track module.
- [ ] Read the platform rules for write-ups.

## 10. References

- HTB Academy and the SOC Analyst job-role path: https://academy.hackthebox.com/
- HTB Labs and Sherlocks: https://app.hackthebox.com/
- Check the official HTB pages for CDSA and LetsDefend updates.
