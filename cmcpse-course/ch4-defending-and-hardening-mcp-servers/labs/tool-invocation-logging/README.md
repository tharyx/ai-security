# Lab: comprehensive logging for tool invocations

**Course exercise:** Configure comprehensive logging for tool invocations · **Lesson:** [06 Logging, monitoring and detection](../../06-logging-monitoring-detection.md) · **Related:** [Module 04, secure-operations](../../../../04-mcp-security/secure-operations/README.md) (MCP08)

Offline. One JSON line per `tools/call` with full context, seven detections, and a **signed, hash-chained audit** with verification and an anchor. Tests: `test_invocation_log.py` (16).

| File | Role |
|---|---|
| [`invocation_log.py`](invocation_log.py) | `InvocationLogger`, `LoggedCaller` (wraps any call so allow, deny and error are all logged), `redact()`, `AuditChain`, `verify()`, `detect()` with `DetectionConfig` |
| [`demo.py`](demo.py) | A short session with a read-then-send chain and repeated denials, then tampering |

Record fields: `ts, seq, event_id, session_id, user, client_id, server, tool, args_hash, args_redacted, result_size, latency_ms, decision, reason, prev_hash, hash, sig`.

```bash
python cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/tool-invocation-logging/demo.py
python -m pytest cmcpse-course/ch4-defending-and-hardening-mcp-servers/labs/tool-invocation-logging
```

Real demo output (the hash lines are shortened here; the real output is full length):

```text
one log line:
  {"args_hash":"267a6f13...b91f","args_redacted":{"api_key":"[REDACTED]","query":"region=EU"},"client_id":"ide-agent","decision":"allow","event_id":"ev-000001","hash":"fccb0c3c...d4d2","latency_ms":0.0,"prev_hash":"0000...0000","reason":"","result_size":7,"seq":1,"server":"crm","session_id":"sess-42","sig":"91689531...1bd0","tool":"read_customers","ts":1760011200.0,"user":"alice"}

detections:
  [high  ] repeated_denials  alice: probing for tools or scopes it may not use
  [high  ] read_then_egress  alice: read_customers then send_email within 60.0s
  [medium] secret_in_args    alice: a secret-like value was passed as a tool argument

chain intact?      yes
after editing #3   record 3: content was changed (hash mismatch)
after cutting tail anchor mismatch: records were cut off the end or appended after the anchor
```

Tamper tests: edit a record, delete a middle record, reorder, **re-hash everything without the key** (the signature fails), and truncate the tail (only the **anchor** catches this).

Lab simplification: HMAC lets the key holder forge; production uses an asymmetric key (Ed25519 or a KMS) and ships records to write-once storage.

## Your tasks

1. Ship `logger.sink` to a file and write a `jq` query that lists all denials per user.
2. Add a rule `tool_sweep`: a user calls five or more different tools in 30 seconds. Write the test first.
3. Add an `approval` field (who approved, the text shown) for tools that need approval. Why must it be inside the signed record?
4. Store the anchor in a second file and write a `verify_files(log, anchor)` command with exit code 1 on failure.
