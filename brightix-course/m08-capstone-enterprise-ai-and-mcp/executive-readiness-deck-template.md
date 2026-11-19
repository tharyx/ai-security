# Executive security readiness deck (template): enterprise AI assistant with RAG and MCP

> **Brightix module 8** · [BX 8] Final Architecture Review & Executive Security Readiness Presentation
> **Fill it from:** the [capstone lab](labs/enterprise-ai-mcp-capstone/README.md) (`demo.py --write OUTDIR` gives `deck-numbers.json`, `scorecard.md`, `review.md`, `threat-model.md`, `incidents.json`) and, for response times, the [module 6 SOAR lab](../m06-ai-security-monitoring-and-soc/labs/ai-soar-playbooks/README.md)
> **Related:** [Capstone architecture defense (deck and panel prep)](../../10-capstone-project/04-architecture-defense-and-interview.md) · [CMCPSE executive one-pager](../../cmcpse-course/ch3-threat-modeling-mcp-architectures/exec-summary-template.md) (use it as the leave-behind) · [Capstone red team and incident exercise](../../10-capstone-project/03-red-team-and-incident-exercise.md) · [AI SOC extension](../../10-capstone-project/05-ai-soc-monitoring-extension.md) · [Enterprise AI reference architecture](../../09-enterprise-architecture/01-enterprise-ai-reference-architecture.md)

**Audience:** CISO, CIO, risk committee or board. **Length:** 12 slides, 15 minutes plus questions. **Rule:** every number on a slide must trace back to a file the lab (or your real test run) produced. If you cannot trace it, do not show it.

## How to fill it from the lab

| Deck field | Lab source | Example value from the lab run |
|---|---|---|
| Verdict | `deck-numbers.json` > `verdict` | READY WITH CONDITIONS |
| Readiness score | `deck-numbers.json` > `readiness_score` | 96.7 / 100 |
| Attacks tested | `deck-numbers.json` > `attacks_tested` | 8 |
| Blocked before / after | `blocked_baseline_pct` / `blocked_hardened_pct` | 0% / 100% (impact-weighted) |
| Blocked by guardrails alone | `blocked_soft_only_pct` | 8.6% |
| Blocked with guardrails OFF | `blocked_hard_only_pct` | 100% |
| Business tasks still working | `benign_working_hardened_pct` | 100% |
| Untested risks | `untested_threats` + `threat-model.md` "Open issues" | TH-10 cost-DoS |
| Top risks | `threat-model.md` threats table, highest LxI first | TH-01 (25), TH-02 (20) ... |
| Conditions / asks | `review.md` "Conditions / asks" | AR-12 partial (TH-10) |
| Detection coverage | `review.md` AR-10, `incidents.json` | every attack raised an alert |
| Time to detect / contain | module 6 `ir_report` metrics | e.g. 18 min / 10 min for the poisoned-doc incident |

Translate each technical item with this pattern: **what could happen -> to whom -> how likely -> what it costs -> what we did -> what is left.**

---

## Slide 1: Bottom line

**Headline:** "The AI assistant is ready for pilot with conditions: all 8 tested attack paths are blocked; one risk needs a decision."

- Verdict: `<READY / READY WITH CONDITIONS / NOT READY>`, readiness `<score>/100`
- One sentence on what the system does for the business
- One sentence on the decision you need today

> **Speaker notes:** Lead with the answer. Executives decide in the first minute whether to trust the rest. Do not open with architecture. Say the verdict, the single most important number (before/after blocked), and the ask. "Ready with conditions" is a strong answer when the conditions are specific and owned.

## Slide 2: What we assessed and how

- Scope: planner, research and action agents; RAG over `<n>` tenants' documents; MCP tools `search_docs`, `send_email`, `read_crm`, `run_report` through one gateway
- Method: threat model (STRIDE + MITRE ATLAS + OWASP LLM and Agentic), red team of `<n>` attacks measured on **impact**, control-by-control validation, SOC detection and playbook test, architecture review (`<n>` checks)
- Out of scope: `<e.g. model provider's own infrastructure, physical security>`

> **Speaker notes:** One slide, no diagrams with 40 boxes. Mention that tests are automated and repeatable (they run in CI), so the result is not a one-off opinion. Say "impact" means an email really left or data was really read, not "the model said something odd".

## Slide 3: Risk posture at a glance

| | Before hardening | Guardrails only | After hardening | After hardening, guardrails off |
|---|---|---|---|---|
| Attacks blocked (impact-weighted) | `<0%>` | `<8.6%>` | `<100%>` | `<100%>` |
| Business tasks working | `<100%>` | `<100%>` | `<100%>` | `<100%>` |

A ready-made visual of this table from the lab run: [scorecard diagram](../../images/bx-m08-scorecard.svg).

> **Speaker notes:** This is the slide people photograph. Explain the last column in one sentence: "even if the AI filter is fooled, the hard controls still stop the attack." Explain the "guardrails only" column: buying a filter product alone would have left most paths open. Avoid false precision: say "all eight" rather than "100.0%" when talking.

## Slide 4: Top risks in business terms

| Risk (business wording) | Technical name (for the appendix) | Likelihood x impact | Status |
|---|---|---|---|
| A shared wiki page tricks the assistant into emailing confidential pricing outside | RAG poisoning / indirect prompt injection (TH-01) | `<25>` | Blocked, tested |
| One customer sees another customer's documents | Cross-tenant retrieval (TH-02) | `<20>` | Blocked, tested |
| A third-party plug-in (MCP tool) turns malicious after we approved it | Rug pull (TH-04) | `<15>` | Blocked, tested |
| A junior user gets data through the assistant's powerful account | Confused deputy (TH-06) | `<16>` | Blocked, tested |
| Someone runs up a large AI bill or slows the service | Cost-DoS (TH-10) | `<9>` | **Not tested: decision needed** |

> **Speaker notes:** Three to five risks, no more. Use words the audience uses: customers, contracts, regulators, money. Keep the OWASP/ATLAS names in the appendix for the technical reviewer. If the board has seen a press story (EchoLeak-style exfiltration, a malicious MCP package), link your risk to it in one sentence.

## Slide 5: What we tested (red team)

- `<8>` attack paths: poisoned documents, cross-tenant access, malicious and changed plug-ins, poisoned tool results, privilege misuse, email exfiltration, system-prompt leak
- All succeeded before hardening; all failed after; all still failed with the AI filters switched off
- Rules of engagement: staging only, fake data and canaries, no real customer data

> **Speaker notes:** Pull from `scorecard.md`. The point is not "we are clever attackers", it is "we proved the controls with evidence". Mention that the tests stay in the pipeline so a future change that breaks a control fails the build.

## Slide 6: Controls deployed

| Control | Plain-English purpose | Stops |
|---|---|---|
| Tenant filter on search (retrieval ACL) | Each customer only searches their own documents | Cross-customer leaks |
| Approved plug-in list with fingerprints (tool pinning) | Only reviewed tools, and they cannot change silently | Malicious or changed plug-ins |
| Least privilege + on-behalf-of | The assistant can only do what the user could do | Privilege misuse |
| Human approval for outbound email | A person checks recipient and reason | Data leaving by email |
| Egress allow-list | Email only to approved domains | Exfiltration |
| Data loss prevention on output | Secrets and markers are redacted | Leaks in answers and emails |
| AI guardrails (input/output filters) | Catch obvious attacks early | Noise reduction (defence in depth) |

> **Speaker notes:** Group as "hard controls" (deterministic, the main defence) and "AI filters" (helpful, bypassable). Executives often assume the AI filter is the security. Correct that gently with slide 3's last column.

## Slide 7: Detection and response readiness

- Telemetry: every tool call logged with user, agent, decision and provenance; no raw prompts or secrets in logs
- Detections: `<n>` rules; every tested attack raised an alert (blocked attempts are visible too)
- Playbooks: evidence first, approval before containment (revoke agent token, disable plug-in, quarantine document, roll back system prompt)
- Response times from the exercise: time to detect `<x>` min, time to contain `<y>` min

> **Speaker notes:** Boards ask "would we know?". Answer with the exercise numbers. Mention NIST SP 800-61 (Rev. 3 aligns incident response to CSF 2.0; verify) to show the process is standard. Be honest about the human approval step: it adds minutes, and that is a deliberate trade-off.

## Slide 8: Residual risk and acceptance asks

| Residual risk | Why it remains | Owner | Ask |
|---|---|---|---|
| Cost-DoS not tested (TH-10) | No per-user token quota yet | `<AI platform lead>` | Fund quota + alert (`<n>` days) **or** accept for pilot with a spend cap |
| Human approval quality | A "rubber stamp" approver lets exfiltration through (tested) | `<Messaging owner>` | Approval training + sampling review |
| New attack techniques | Tests cover known paths | `<CISO>` | Quarterly red-team refresh |

> **Speaker notes:** This is where you earn trust. Every row needs an owner and a decision: accept, fund, or stop. Write the acceptance in the risk register with an expiry date. Do not let "residual" mean "ignored".

## Slide 9: Metrics we will report monthly

- Attack paths tested and % blocked (impact-weighted), with guardrails on and off
- Alerts per week and % with real impact; false-positive rate of AI detections
- Time to detect / time to contain for AI incidents
- Plug-in (MCP tool) inventory: approved, pinned, changed this month
- Spend per user and anomalies (once TH-10 is fixed)
- Governance: % of AI use cases with a threat model and an owner (maps to NIST AI RMF "Govern/Map/Measure/Manage" and ISO/IEC 42001 controls; verify mappings)

> **Speaker notes:** Pick four to six metrics you can actually produce every month. Trend matters more than the first value.

## Slide 10: Roadmap (30 / 60 / 90 days)

| 30 days | 60 days | 90 days |
|---|---|---|
| Token quota + cost alert (closes TH-10) | Port detections to the SIEM (KQL/SPL) | External red-team review |
| Approver training and sampling | SOAR playbooks with approval gates in production | Expand to the next two AI use cases |
| Pin all MCP tools in the gateway | Automated plug-in change review | Tabletop exercise with legal and comms |

> **Speaker notes:** Tie each item to a risk on slide 4 or 8. If an item does not reduce a named risk, cut it.

## Slide 11: Budget and asks

- People: `<n>` FTE-months for `<items>`
- Tools/licences: `<SIEM ingestion for AI telemetry, gateway, scanner>`; estimate `<amount>` (verify vendor pricing)
- Decisions today: 1) approve pilot with conditions; 2) accept or fund TH-10; 3) name owners for slide 8
- Regulatory note (if in the EU): map the use case under the EU AI Act; high-risk obligations apply later (dates were moved by the 2026 Omnibus amendment; confirm with legal)

> **Speaker notes:** Make the ask concrete and small enough to approve in the meeting. Separate "must have before go-live" from "nice to have".

## Slide 12 (appendix): Evidence and method

- Links: threat model report, scorecard, review checklist, incident outputs, test run ID
- Framework tags: OWASP Top 10 for LLM Applications (2026 names), OWASP Agentic Top 10, MITRE ATLAS technique names (IDs verified on `<date>`), NIST AI RMF 1.0 + Generative AI Profile (NIST AI 600-1), ISO/IEC 42001:2023
- Assumptions and limits: staging environment, simulated model in the lab, known attack paths only

> **Speaker notes:** You will not present this slide, but the technical reviewer will read it. It protects you when someone asks "how do you know?".

---

## Checklist before you present

- [ ] Every number traces to a file from a dated test run
- [ ] Top risks are in business language; technical names only in the appendix
- [ ] Each residual risk has an owner and a decision (accept / fund / stop) with a date
- [ ] You can explain the "guardrails off" column in one sentence
- [ ] The one-page leave-behind (CMCPSE exec template) matches the deck
- [ ] Rehearsed to 15 minutes; three likely questions prepared (cost, "would we know?", "what if the AI vendor is breached?")
