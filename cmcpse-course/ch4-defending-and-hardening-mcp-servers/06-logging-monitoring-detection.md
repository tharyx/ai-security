# Lesson 06: Logging, monitoring and detection

> **Chapter 4** · **Time:** ~4 hours · **You will:** decide what to log for MCP, write structured tool-invocation records with full context, detect abusive patterns, monitor whole agentic pipelines, alert on MCP attack indicators, and build audit trails with non-repudiation.

| | |
|---|---|
| **Syllabus lines** | Logging, Monitoring, and Detection (6 lines) |
| **Already in this repo (read first)** | [Module 04, secure-operations](../../04-mcp-security/secure-operations/README.md) §2.4 (MCP08: attributable decisions, hash chain, anchor, detections); [Module 05, monitoring and response](../../05-agent-security/monitoring-and-response/README.md) (rogue agent detection, kill switch); [Module 06, runtime security](../../06-ai-devsecops/runtime-security/README.md) (spans, detection rules) |
| **Lab** | [`tool-invocation-logging`](labs/tool-invocation-logging/README.md) (16 tests) |

---

## 1. What to log in MCP environments

Log events from **every layer**. Each answers a different question.

| Source | Events | Question |
|---|---|---|
| Host / client | Server connect, `initialize` and negotiated capabilities, `tools/list`, tool-definition changes (hash), user approvals (with the exact action text), denials, errors | What did the agent see and what did the human approve? |
| Gateway / firewall | Allow, block, redact, quarantine, rate-limit decisions with reasons | What was stopped? |
| MCP server | Authentication result, `tools/call` and `resources/read` with decision, latency, result size, downstream calls | What ran? |
| Authorization server | Token issued (client, scopes, audience), refresh, revoke, failed logins | Who got which rights? |
| Vault / secret store | Reads, lease create/renew/revoke, policy denials | Who touched which secret? |
| Platform | Process starts (command line), network connections, config file changes | Did a server start that nobody approved? |

**Never log:** raw tokens, API keys, passwords, full prompts and tool results with personal data (log size and a hash), `Authorization` headers, secrets in arguments. Redact before the log line is written ([lab `redact()`](labs/tool-invocation-logging/invocation_log.py)). Keep logs at the data classification of the data they describe.

## 2. Logging tool invocations with full context

One JSON line per call, always the same fields, easy to query and to sign. The lab schema:

```json
{"ts": 1760011200.0, "seq": 1, "event_id": "ev-000001", "session_id": "sess-42",
 "user": "alice", "client_id": "ide-agent", "server": "crm", "tool": "read_customers",
 "args_hash": "267a6f...", "args_redacted": {"query": "region=EU", "api_key": "[REDACTED]"},
 "result_size": 7, "latency_ms": 0.0, "decision": "allow", "reason": "",
 "prev_hash": "000...", "hash": "fccb0c...", "sig": "916895..."}
```

Why each field:

* **user + client_id + session_id:** who and through which app (the human, not only the agent). Add a trace id to follow one task across servers.
* **server + tool:** what ran. Use the namespaced name (`crm.read_customers`).
* **args_hash:** SHA-256 of the canonical raw arguments. It proves *what was sent* (for example to match a leaked value later) without storing it.
* **args_redacted:** useful for investigation, secrets masked, long values truncated.
* **result_size, latency_ms:** exfiltration and abuse show up as size and timing.
* **decision + reason:** allow, deny, error. **Log denials**; they are the best early warning.

Rules: log **after** the decision but **before** returning (so a crash still leaves a record), log errors as the **class name** only (messages can carry secrets), use the same clock source everywhere (NTP), and ship to a central store.

## 3. Detecting anomalous and abusive tool usage patterns

Detections over those records (all in the lab, each with a test):

| Rule | Signal | Severity | Why |
|---|---|---|---|
| `burst` | Many calls from one user in a short window | Medium | Loops, scraping, runaway agent (ASI08) |
| `repeated_denials` | Several denials in a window | High | Probing for tools, scopes or paths |
| `read_then_egress` | A sensitive read followed by an egress tool within a minute | High | The classic exfiltration chain, including cross-server |
| `large_result` | Result size above a threshold | Medium | Bulk data pull |
| `new_tool` | First use of a tool outside the user's baseline | Low | Scope creep, new capability |
| `secret_in_args` | A secret-like value in arguments | Medium | Credential handling bug or injection |
| `off_hours` | Activity outside business hours | Low | Stolen credentials or unattended agent |

Start with a baseline period, tune thresholds to cut noise, and treat each rule like code (tests, owner, runbook). Detections that fire too often are ignored. Prefer **sequence** rules (read then send) over single-event rules. Combine with an identity risk score.

## 4. Monitoring agentic pipelines for suspicious behavior

A pipeline is more than one call: model → host → several servers → backends. Watch:

* **Tool definition changes** (hash differs from the pin): possible rug pull.
* **New or unknown servers** in configs or on the network (shadow servers).
* **Cross-server flows:** data read from server A appearing in arguments to server B.
* **Goal drift:** calls unrelated to the task or ticket (compare tools used with the task's tool list).
* **Injection indicators:** gateway quarantines, tool results with instruction phrases, hidden Unicode.
* **Cost and quota:** tokens and calls per task versus the baseline (denial of wallet).
* **Human approval metrics:** approval rate and time (fatigue), approvals of unusual actions.
* **Kill switch:** the ability to suspend an agent, a server or a token at once ([Module 05](../../05-agent-security/monitoring-and-response/README.md)).

Use **OpenTelemetry-style traces** (a trace per task, a span per call) so one view shows the whole chain; [Module 06 runtime security](../../06-ai-devsecops/runtime-security/README.md) builds spans and rules.

## 5. Alerting on indicators of MCP-based attacks

| Indicator | Likely attack | First response |
|---|---|---|
| A pinned tool's hash changed | Rug pull, supply chain | Quarantine the tool, notify owner, diff |
| Firewall quarantine on a result | Indirect prompt injection | Check the source document or server; block the source |
| Denial burst from one client | Scope probing, compromised client | Throttle, revoke the token |
| `read_then_egress` | Exfiltration | Require approval, suspend session, review args |
| Token used with a new audience or from a new place | Token theft or passthrough | Revoke, rotate |
| Server started with an unapproved command line | Config tampering, shadow server | Stop the process, diff the config |
| Audit chain verification fails | Log tampering | Treat as an incident; use the anchor and offsite copy |
| Secret pattern in args, results or logs | Leak | Rotate the secret, find the sink |

Alert design: **one owner per alert, a runbook link, severity that maps to a response time, and a suppression rule that expires**. Send high alerts to a person, low alerts to a daily report.

## 6. Audit trails and non-repudiation for tool calls

**Non-repudiation** means a user or system cannot credibly deny an action, and nobody can credibly deny that the record is genuine. In practice this needs:

1. **Attribution:** the record names the authenticated user and client.
2. **Integrity:** records are **hash-chained** (each includes the previous hash) so editing, deleting or re-ordering is visible.
3. **Authenticity:** each record is **signed** (HMAC with a secret key, or better an asymmetric signature such as Ed25519 or a KMS key, so verifiers cannot forge).
4. **Completeness:** an **anchor** (record count and last hash) stored elsewhere detects **truncation** of the tail, which the chain alone cannot see.
5. **Timestamps** from a trusted source; for strong proof use a trusted timestamp service or transparency log.
6. **Retention and access control:** write-once storage, separate keys and admin from the application, a retention period set by policy and law.
7. **Evidence of consent:** for actions needing approval, store *what the human saw*, not only that they clicked.

The lab proves each point with tests: edit one record (hash mismatch), delete a middle record (sequence and `prev_hash`), reorder, re-hash everything without the key (signature fails), truncate the tail (only the anchor catches it). Limits to state honestly: with HMAC, anyone holding the key can forge; a compromised logging host can sign false records going forward; and a log proves what the **system recorded**, not that the model's reasoning was right.

## 7. Quick check

1. Which fields let you prove what arguments were sent without storing the secret?
2. Why log denials?
3. Name one attack the hash chain alone cannot detect, and what detects it.
4. Write a sequence rule for "customer data read, then external email within 60 seconds".

## 8. References

* OWASP Logging Cheat Sheet; NIST SP 800-92 (log management); OpenTelemetry semantic conventions for traces.
* OWASP MCP08 Lack of Audit and Telemetry (beta list).
* [Module 04, secure-operations](../../04-mcp-security/secure-operations/README.md); [Module 06, runtime security](../../06-ai-devsecops/runtime-security/README.md).
