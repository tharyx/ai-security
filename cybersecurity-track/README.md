# Cybersecurity Track: Cloud Security & SOC

**From Oracle DBA / DevOps → Cloud Security & SOC Analyst, in about 24 weeks.**

This track covers the security foundations your current job needs right now: IT and networking basics, security concepts, SOC work, SIEM (Microsoft Sentinel and Splunk), EDR/MDR, vulnerability management, cloud security, risk and ISO/IEC 27001, plus the certifications, soft skills and public profile that get you hired and promoted.
Everything for this track lives in this one folder. The [AI security roadmap](../README.md) in the rest of the repo builds on top of it.

> **Your advantage:** you already know databases, Linux/Unix, backups, change control, auditing and automation. Many SOC analysts start without any of that. Each lesson has a **"From DBA to security"** box that connects new ideas to what you already know.

## Modules

| # | Module | Weeks | Certification it supports | Lab |
|---|---|---|---|---|
| 00 | [Career plan & certifications](00-career-plan-and-certifications/) | Week 1, then ongoing | All | Study plan |
| 01 | [IT fundamentals](01-it-fundamentals/) | 1–2 | CompTIA A+ | Windows/Linux log analysis |
| 02 | [Networking](02-networking/) | 2–4 | CompTIA Network+ | Subnetting, firewall and DNS log analysis |
| 03 | [Security foundations](03-security-foundations/) | 4–7 | Security+ · ISC2 CC | Password storage, phishing headers |
| 04 | [Risk management & ISO/IEC 27001](04-risk-management-and-iso27001/) | 7–8 | Security+ · ISO 27001 | Risk register, SoA gap checker |
| 05 | [SOC fundamentals](05-soc-fundamentals/) | 3–6 | CySA+ · SAL1 · CDSA | Alert triage simulator |
| 06 | [SIEM: Sentinel & Splunk](06-siem-sentinel-splunk/) | 5–10 | SC-200 · Splunk | Mini-SIEM + KQL/SPL exercises |
| 07 | [EDR / XDR / MDR](07-edr-xdr-mdr/) | 9–11 | SC-200 · CySA+ | Process-tree detections |
| 08 | [Vulnerability management](08-vulnerability-management/) | 11–13 | CySA+ · Security+ | CVSS + EPSS + KEV prioritizer |
| 09 | [Pentesting fundamentals](09-pentesting-fundamentals/) | 13–15 | Security+ · PenTest+ (idea) | SQL injection vs fix, report generator |
| 10 | [Cloud security](10-cloud-security/) | 6–12 (in parallel) | AZ-500 · AWS Security | CloudTrail detections, IAM analyzer |
| 11 | [Database security](11-database-security/) | 12–14 | Your DBA strength | Oracle audit-log detections |
| 12 | [Soft skills](12-soft-skills/) | Ongoing | Interviews | Report and handover templates |
| 13 | [Profile & portfolio](13-profile-and-portfolio/) | Ongoing | TryHackMe · HTB · blog | Trackers and templates |

Full week-by-week plan: [00-career-plan-and-certifications/04-24-week-plan.md](00-career-plan-and-certifications/04-24-week-plan.md) · Progress: [PROGRESS.md](PROGRESS.md)

## Why this order

Your **job** needs SOC, SIEM and cloud security now, so modules 05, 06 and 10 start early and run alongside the foundations (01–03). The certification order (A+ topics → Network+ → ISC2 CC → Security+ → SC-200/Splunk → CySA+ or a cloud security cert) follows the foundations. See [the certification roadmap](00-career-plan-and-certifications/01-certification-roadmap.md).

## Certifications at a glance (verify before booking)

| Cert | Status (Nov 2026) | Advice |
|---|---|---|
| CompTIA A+ (220-1201/1202) | Current | Study the topics; the exam is optional with your experience |
| CompTIA Network+ (N10-009) | Current | Worth it if networking is your weakest area |
| ISC2 CC | **Paid now**: the free program closed to new people in May 2026 | Good first security cert; cheap and quick |
| CompTIA Security+ | **SY0-801 launched 17 Nov 2026**; SY0-701 available until about mid-2027 | Core cert for SOC jobs |
| Microsoft SC-200 | Current | Best match for a Sentinel / Defender SOC job |
| Splunk Core Certified User / Power User | Verify current names | If your SOC uses Splunk |
| CySA+ / AZ-500 / AWS Security Specialty | Verify current versions | Next step after Security+ |

## How every module works

**Learn** (lesson) → **do** (offline lab in `lab/`, `python -m pytest` to check) → **practice** (TryHackMe / HTB rooms named in the lesson) → **write** (journal + blog post) → **answer** (interview questions out loud).

```powershell
python -m pytest cybersecurity-track
```

## Your weekly routine (10–12 h)

| Time | What |
|---|---|
| 3 h | Lessons for the current module |
| 3 h | Repo labs, plus the job tools you have (Sentinel/Splunk at work) |
| 3 h | TryHackMe / HTB rooms for the same topic |
| 1 h | Certification practice questions |
| 1 h | Write: journal, case notes, one blog post every 2 weeks |
| 1 h | Interview practice and soft skills |

## Rules

- Practice attacks **only** on platforms built for it (TryHackMe, HTB) or on systems you own. Never test your employer's systems without written permission.
- Never put real company logs, IPs, usernames or incidents into this public repo or your blog. Sanitize everything.
- Your PDF library is in `Documents/` (local only). Each module lists which documents to read.
