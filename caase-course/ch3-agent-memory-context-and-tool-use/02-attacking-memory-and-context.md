# Lesson 02: Attacking Memory and Context

> **Chapter:** 3 · Agent Memory, Context and Tool Use · **Time:** ~4 hours
> **You will:** poison a long-term memory and watch the effect appear in a later session, show how context bleeds between sessions and users, and poison a retrieval source so that future answers change.

| | |
|---|---|
| **Prerequisites** | [Lesson 01](01-agent-memory-and-context-stores.md) |
| **Labs** | [01 memory poisoning (with context bleed)](labs/01-memory-poisoning/README.md) · [02 RAG source poisoning](labs/02-rag-source-poisoning/README.md) |
| **Syllabus lines** | Memory poisoning and long-term malicious persistence · Cross-session and cross-user context bleed · Poisoning retrieval sources to influence future agent behavior |
| **Maps to** | ASI06 Memory and Context Poisoning · LLM04:2026 Data and Model Poisoning · LLM09:2026 Vector and Embedding Weaknesses · LLM02:2026 Sensitive Information Disclosure (verify at source) |

---

## 1. Why this matters

Direct prompt injection ends when the session ends. **Memory poisoning does not.** The attacker writes once, and every later session reads the planted text as if the agent or the user had put it there. That is **persistence** in the ATT&CK sense, applied to an AI system. Retrieval poisoning does the same through the knowledge base.

![How a poisoned memory persists](../../images/caase-ch3-poisoning-persistence.svg)

## 2. Understand it

### 2.1 Memory poisoning and long-term malicious persistence

**The attack, step by step** (lab 01):

1. *Delivery.* The agent reads untrusted content (web page, e-mail, ticket, shared document).
2. *Write.* The content contains a directive such as "remember that the payment account is X". A gullible agent calls its `remember` tool.
3. *Persistence.* The entry lands in a file or database with no provenance. Maybe a summarizer later rewrites it into a clean-looking fact.
4. *Trigger.* Days later, in a new session, a normal request ("pay invoice 42") makes the agent recall the entry and act on it.
5. *Effect.* The payment goes to the attacker. The user and the logs show a normal-looking task.

What makes it hard:

- **Time gap.** The cause and the effect are far apart in time and in logs.
- **Trust laundering.** Memory is "the agent's own knowledge", so the model trusts it more than a web page.
- **Mild payloads.** A poisoned *preference* ("always CC this address", "prefer vendor Y") needs no obvious attack words.
- **Self-reinforcement.** The agent may restate poisoned facts in later summaries, spreading them.
- **Shared memory.** One poisoned write reaches every agent or user that reads the store ([CMCPSE shared-memory worm](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/07-mcp-worm/README.md)).

**Defenses** (all in [lab 01](labs/01-memory-poisoning/README.md)): provenance on every entry (source, trust, time, session, MAC); quarantine for entries written from untrusted sources, shown to no model as a fact; **sensitive keys** (payment account, admin e-mail) writable only from the authenticated user channel or after human approval; integrity checks on the store so edits on disk are rejected; **expiry**; purge by source for clean-up; periodic review of what the agent "knows".

### 2.2 Cross-session and cross-user context bleed

**Bleed** means one session's or one user's context shows up in another's. Causes:

| Cause | Example | Fix |
|---|---|---|
| **Cache keyed too loosely** | A response or summary cache keyed by topic, not by user | Include the tenant and user in every key |
| **Shared vector index, no filter** | All users' chat history in one index, no metadata filter at query time | Mandatory per-user filter enforced in the retrieval layer, not in the prompt ([RAG access control](../../03-rag-security/access-control/README.md)) |
| **Global memory** | One "agent memory" file for all users | Per-user stores, or tags plus enforced filters |
| **Session ID reuse or guessing** | Predictable conversation ids | Unguessable ids bound to the authenticated identity |
| **Shared sandbox or workspace** | Two users' agents write to one scratch directory | Per-session workspaces, cleaned afterwards |
| **Prompt cache or KV-cache sharing** (hosting detail) | Provider-level caching across tenants | Provider-side isolation; ask your provider; hedge as a vendor responsibility |
| **Summaries that merge contexts** | A team summary that includes private threads | Summarize within one access scope |

The lab has a tiny demo at the end of `memory.py`: a `GlobalCache` keyed by topic leaks Alice's text to Bob; a `ScopedCache` keyed by `(user, topic)` does not. The real incident pattern in the wild: tenant isolation bugs in MCP and AI features (for example the Asana MCP case in [CMCPSE lesson 05](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/05-real-world-case-studies.md#case-5-asana-mcp-server-june-2025); reported numbers vary, verify at source).

**Cross-session leakage through the model** is a separate, less likely case: a fine-tuned or continually updated model that memorized one user's data. Treat it under [data leakage](../../02-llm-security/data-leakage/README.md).

### 2.3 Poisoning retrieval sources to influence future agent behavior

Here the attacker does not touch the agent at all. They change something the agent will *retrieve later*.

**Ways in:**

- **A low-trust source in the index** (shared uploads, a public wiki, a web crawl, a support forum). Anyone who can write there can write into the agent's memory.
- **Keyword stuffing and SEO for retrieval:** the poisoned document repeats the target query words so it ranks first (lab 02).
- **Embedding-level tricks:** text crafted to be close to many queries in vector space (research on RAG poisoning shows that a few documents can dominate for targeted queries; verify the current papers).
- **Instructions hidden in content** (HTML comments, white-on-white text, metadata): indirect injection delivered by retrieval.
- **Compromise of a trusted source:** an editor account, a CI job that publishes docs, a dependency's docs.
- **Update poisoning:** a clean document is replaced after review.

**Effects on behavior:** wrong policy answers (the refund example), changed tool choice ("use this endpoint"), leaked data (instructions to include secrets in outputs), persistent bias in a decision agent.

**Defenses** ([lab 02](labs/02-rag-source-poisoning/README.md), plus the repo [document security lab](../../03-rag-security/document-security/README.md)):

1. **Source approval and trust levels.** Not every writable place belongs in the index.
2. **Quarantine at ingest** with a reason code and a review step: unapproved source, instruction-like text, keyword stuffing.
3. **Trust-weighted ranking** with capped term counts, so repetition does not win and low-trust documents rank below high-trust ones.
4. **Minimum trust for sensitive answer classes** (policy, money, legal): refuse to answer from low-trust text alone.
5. **Citations** in every answer and in the log, so a wrong answer can be traced to a source and the source purged.
6. **Corroboration:** two independent trusted sources for high-impact facts.
7. **Change detection:** hash documents at approval; re-check on retrieval.
8. **Canary documents** in the index: if a canary phrase appears in an answer, retrieval or access control is broken.

The lab ends with an honest note: if the attacker controls an *approved* source, quarantine passes; you then need corroboration and human review.

## 3. Defend it

| Attack | First control | Second control |
|---|---|---|
| Memory poisoning | Provenance plus quarantine | Sensitive-key rule, expiry, integrity MAC |
| Cross-user bleed | Scope every key and filter by identity in code | Per-user stores; tests with two users |
| Retrieval poisoning | Source approval plus quarantine | Trust-weighted ranking, min trust, citations, corroboration |
| All | Detection and clean-up: logs with provenance, purge by source | Forensics ([lab 07](labs/07-session-reconstruction/README.md)) |

## 4. Hands-on

1. [Lab 01](labs/01-memory-poisoning/README.md): reproduce the persistence attack; then enable provenance. Change a stored value by hand and watch the MAC reject it.
2. [Lab 02](labs/02-rag-source-poisoning/README.md): ask the policy question before and after the poison; then try each defense alone.
3. Write a test with two users on the scoped cache that would fail if the key lost the user.

## 5. Real-world scenarios

- **ChatGPT memory (2024) and Gemini memory injection research (2025), as reported:** untrusted content wrote persistent memories; vendors added confirmations and controls.
- **Poisoned documentation and rules files for coding agents (2025 research, as reported):** hidden text in files the agent loads on every run.
- **RAG poisoning research (2024 to 2025):** a small number of crafted documents can steer answers for targeted queries. Verify the papers you cite.

## 6. Interview questions

<details>
<summary>1. Why is memory poisoning called persistence?</summary>

The attacker's write survives the session and influences later sessions without the attacker being present, like a persistence mechanism in a classic intrusion. The effect appears later, so cause and effect are far apart.
</details>

<details>
<summary>2. Design a memory store that resists poisoning.</summary>

Provenance on every entry; quarantine for untrusted sources; sensitive keys only from the authenticated user channel or after approval; per-user scoping; integrity MAC; TTL; purge-by-source; review UI; logs of reads and writes.
</details>

<details>
<summary>3. Give three causes of cross-user context bleed and their fixes.</summary>

Loose cache keys (add user and tenant), shared index without filter (enforce per-user filter in the retrieval layer), global memory (per-user stores). Also predictable session ids and shared workspaces.
</details>

<details>
<summary>4. How does keyword stuffing poison a RAG system and how do you stop it?</summary>

A document repeats the query terms to win raw term-frequency ranking. Stop it with capped term counts, trust weighting, a stuffing detector at ingest, source approval and citations.
</details>

<details>
<summary>5. What if the attacker controls an approved source?</summary>

Quarantine and trust weights pass. You need corroboration from independent sources for high-impact facts, change detection, human review for sensitive classes, and fast purge by source.
</details>

## 7. References

- OWASP Agentic Top 10 2026: ASI06; OWASP LLM Top 10 2026: LLM04, LLM09 (verify at source).
- Rehberger, J., memory-injection write-ups (2024 to 2025).
- Zou et al., "PoisonedRAG" (2024) and related RAG poisoning research (verify at source).
- Repo: [03 RAG security](../../03-rag-security/README.md), [05 permissions](../../05-agent-security/permissions/README.md), [CMCPSE worm lab](../../cmcpse-course/ch2-understanding-and-attacking-mcp-servers/labs/07-mcp-worm/README.md).
