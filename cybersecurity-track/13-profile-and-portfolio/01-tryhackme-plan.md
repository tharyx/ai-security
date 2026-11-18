# 01. TryHackMe Plan

> **Module:** 13 · Profile and Portfolio · **Start:** week 1 · **Time:** 1 to 2 hours per week
> **You will:** follow Cyber Security 101, then SOC Level 1, then SOC Level 2, pick rooms that match each track module, and track the work.
> **Maps to:** Security+ foundations (Cyber Security 101) · SOC analyst skills · TryHackMe certifications SAL1 and SAL2

## 1. Why it matters

TryHackMe (THM) teaches by doing, in the browser, with guided rooms. It is a good fit while you study theory, because every module in this track has a room that practices it. Finished paths and certificates also appear on your profile, which recruiters can see.

## 2. The three paths (verified, Nov 2026)

| Order | Path | What it builds |
|---|---|---|
| 1 | **Cyber Security 101** | Broad foundations: networking, Linux and Windows basics, web, security tools, and early defensive ideas |
| 2 | **SOC Level 1** | Alert triage, SIEM use, phishing and log analysis, threat intelligence, endpoint and network monitoring |
| 3 | **SOC Level 2** | Deeper investigations, incident response, threat hunting, detection engineering |

Certifications: **SAL1** goes with SOC Level 1 and **SAL2** with SOC Level 2 (TryHackMe's Security Analyst Level 1 and 2 certifications). **Check the official page before booking:** exam format, price and requirements change.

Names of individual rooms inside these paths change over time. This lesson does not list room names. Instead, use the method below.

## 3. How to pick rooms for each track module

Rule: **one track module a week, two rooms on the same theme.** Open the path, read the room list, and use the search box on the site.

| Track module | Search terms on THM | What to look for in a room |
|---|---|---|
| 01 IT fundamentals | Windows, Linux, command line | Hands-on file, process and service commands |
| 02 Networking | Wireshark, nmap, TCP, DNS, packets | A room where you open a capture or scan |
| 03 Security foundations | cryptography, hashing, authentication | Short concept rooms |
| 04 Risk and ISO 27001 | governance, risk, frameworks | Often reading-style rooms. Take notes only |
| 05 SOC fundamentals | SOC, triage, phishing, incident | Rooms with alerts to classify |
| 06 SIEM | Splunk, Elastic, Sentinel, logs | A room with a live SIEM you query |
| 07 EDR/XDR | endpoint, Sysmon, Windows event logs | Reading Sysmon or event logs |
| 08 Vulnerability management | vulnerability, Nessus, OpenVAS | Scanning and reading reports |
| 09 Pentesting basics | web, SQL injection, Metasploit | Do only in the provided room machines |
| 10 Cloud | AWS, cloud, S3 | Check page scope; some rooms need accounts |
| 11 Database | SQL, SQL injection, database | Attack-side rooms help you think like the attacker |

## 4. Sample schedule

| Weeks | Focus |
|---|---|
| 1 to 8 | Cyber Security 101, aligned with modules 01 to 03 |
| 9 to 20 | SOC Level 1, aligned with modules 05 to 08 |
| 21 to 36 | SOC Level 2, aligned with cloud, database and your job work. Consider SAL1 when you finish SOC Level 1 |

Adjust to your real pace. A slow week is fine. A zero week twice in a row is a signal to reduce scope.

## 5. How to work a room (checklist)

1. Read the objectives. Write them in your tracker.
2. Do tasks **without** hints first, for 10 minutes.
3. Take notes in your own words (commands, why, what you saw).
4. At the end, write one "SOC use" sentence: where would an analyst use this?
5. Log in the tracker: [trackers/tryhackme-rooms.md](trackers/tryhackme-rooms.md).

## 6. Three realistic scenarios

1. **Stuck on a room for 90 minutes.** Take a hint, then write down exactly what you did not know. That note is your real lesson.
2. **Too many rooms, no learning.** If you cannot explain a room in 3 sentences next day, redo it slowly and write notes.
3. **The room needs a paid subscription.** Check the free content first; choose one paid month only when you have a plan to use it daily.

## 7. Common mistakes

- Speed-running for points, with no notes.
- Copying other people's answers.
- Posting flags (see [etiquette](03-platform-etiquette.md)).
- Only doing offensive rooms when your job is defense.

## 8. Interview questions

<details><summary><b>Q1. Which TryHackMe paths did you complete and what did you learn?</b></summary>
Give the path names, one skill from each (for example triaging a phishing alert, writing a Splunk search), and one project where you applied it, such as a lab from this repo.
</details>

<details><summary><b>Q2. Walk me through how you would triage a suspicious login alert.</b></summary>
Check user, source IP and location, time, device, MFA result, and recent activity. Compare to baseline, look for related alerts, decide benign, suspicious or true positive, and escalate or contain with notes.
</details>

<details><summary><b>Q3. How do you learn a new tool quickly?</b></summary>
Pick one real question, read the quick-start, do a guided room, then use the tool on a lab dataset and write down the three commands you will reuse.
</details>

<details><summary><b>Q4. What is SAL1 and why might you take it?</b></summary>
It is TryHackMe's Security Analyst Level 1 certification. It shows practical SOC skill. Check the official page for the current format and fee.
</details>

<details><summary><b>Q5. How does THM practice connect to your cloud security work?</b></summary>
SIEM and log rooms train the same query and triage skills I use on CloudTrail, Entra logs and database audit logs.
</details>

## 9. Checklist

- [ ] Tracker created and first room logged.
- [ ] A weekly time slot saved on my calendar.
- [ ] Read the etiquette lesson.
- [ ] Each week: two rooms matching the track module.

## 10. References

- TryHackMe learning paths: https://tryhackme.com/
- Check the official certification pages for SAL1 and SAL2 before booking.
- Track modules: [05](../05-soc-fundamentals/), [06](../06-siem-sentinel-splunk/), [10](../10-cloud-security/), [11](../11-database-security/)
