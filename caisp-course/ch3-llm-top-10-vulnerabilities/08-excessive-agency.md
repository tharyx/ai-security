# 08. Excessive Agency (LLM08 in 2023)

> **Maps to:** 2023 LLM08 Excessive Agency | 2025 LLM06 Excessive Agency | 2026 03 Excessive Agency.
> **Time:** 1 hour. **Deep lessons in this repo:** [05-agent-security/permissions](../../05-agent-security/permissions/README.md) (permissions, policy, budgets), and the rest of [05-agent-security](../../05-agent-security/README.md) (agent abuse, goal hijack, multi-agent). This page keeps the course sub-topics short.

## Why this matters

When an LLM can only talk, a bad answer is text. When it can **act** (send mail, change records, run code, spend money), a bad answer is an incident. Excessive Agency is the gap between what the agent *needs* to do and what it is *allowed* to do. It makes every other bug worse: a prompt injection on a read-only assistant is an annoyance; on an assistant that can delete files it is a breach. OWASP moved it from 8th (2023) to 3rd (2026) as agents became common.

## Excessive permissions and autonomy

OWASP groups the problem into three causes. Use this wording on the exam:

| Cause | Meaning | Example |
|---|---|---|
| **Excessive functionality** | The agent has tools it does not need | A "summarize my inbox" agent can also delete and send mail |
| **Excessive permissions** | The tools run with more rights than needed | A read-only task uses an admin database account |
| **Excessive autonomy** | Risky actions run without a human or policy check | A refund of any size is approved by the model alone |

Also remember:

- **Whose authority?** Agents should act with the *user's* rights, not a shared super-account (confused deputy).
- **The trigger is often text.** Injected instructions in a document can make the agent use its excess power.
- **Open-ended tools are the worst offenders:** shell, raw SQL, "browse any URL", "call any API".

## Mitigating excessive agency

| Control | Detail | Type |
|---|---|---|
| Minimize tools | Give the agent only the tools for this task; split big agents into narrow ones | Hard |
| Minimize permissions | Scoped credentials, read-only by default, row and field limits | Hard |
| Use the user's identity | Authorize each call as the end user (OAuth on behalf of the user) | Hard |
| Human in the loop | Approval for destructive, financial, external-send and irreversible actions | Hard (process) |
| Policy engine | A rule check in code before each tool call (amount limits, allowed recipients) | Hard |
| Budgets and limits | Step caps, spend caps, rate limits | Hard |
| Validate tool arguments | In the tool, not in the prompt | Hard |
| Log and audit | Every call, with who, what, why; alert on anomalies | Process |
| Test | Probe suites for hijack and misuse (see below) | Process |

What does not work: telling the model "do not delete anything" in the prompt. That is a request, not a control.

## Hands-on

- Repo labs: [permissions lab](../../05-agent-security/permissions/lab/) (a refund agent with and without a policy layer).
- Chapter 4 lab [llm-agent-vuln-scan](../ch4-ai-attacks-and-defenses-devops/labs/llm-agent-vuln-scan/README.md): probes for goal hijack, tool misuse and excessive permissions against a vulnerable and a hardened agent.

## Interview Q&A

<details><summary><b>Q1. Name the three root causes of Excessive Agency.</b></summary>
Excessive functionality (too many tools), excessive permissions (tools run with too much privilege), and excessive autonomy (risky actions without approval or policy).
</details>

<details><summary><b>Q2. A support agent can issue refunds. How do you limit it?</b></summary>
Give it only a refund tool with a typed amount and order ID; cap the amount in code; require human approval above a threshold; use the customer's session identity to verify the order belongs to them; rate-limit and log every refund; test hijack attempts via documents and messages.
</details>

<details><summary><b>Q3. Why is Excessive Agency ranked higher now than in 2023?</b></summary>
Agents that take actions became common, so the impact of prompt injection and mistakes grew. The risk multiplies the other risks.
</details>

## References

- OWASP LLM Top 10 (excessive agency): https://genai.owasp.org/
- OWASP Agentic Security Initiative materials (verify current names and IDs at source)
- Repo: [05-agent-security/permissions](../../05-agent-security/permissions/README.md)
