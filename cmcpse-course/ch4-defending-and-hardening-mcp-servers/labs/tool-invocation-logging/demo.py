"""Demo: structured tool-invocation log, detections and a tamper-evident audit chain."""

import copy
import json

from aisec_lab import load_lab_module

il = load_lab_module(__file__, "invocation_log")
KEY = b"demo-audit-key-demo-audit-key-32"
T0 = 1_760_011_200.0   # a fixed time so the output is stable


class Clock:
    t = T0

    def __call__(self):
        return self.t


clock = Clock()
chain = il.AuditChain(KEY)
logger = il.InvocationLogger(chain, clock)
who = il.Identity("alice", "ide-agent", "sess-42")
backend = lambda server, tool, args: "42 rows" if tool == "read_customers" else "sent"   # noqa: E731
caller = il.LoggedCaller(backend, logger, allow=lambda w, s, t: "tool not allowed for role" if t == "drop_table" else None)

caller(who, "crm", "read_customers", {"query": "region=EU", "api_key": "sk-DEMOKEYDEMOKEY12"}); clock.t += 4
caller(who, "mail", "send_email", {"to": "x@example.org", "body": "hi"}); clock.t += 1
for _ in range(3):
    try:
        caller(who, "db", "drop_table", {"name": "users"})
    except PermissionError:
        pass
    clock.t += 2

print("one log line:\n ", logger.sink[0], "\n")
print("detections:")
for a in il.detect(chain.records):
    print(f"  [{a['severity']:<6}] {a['rule']:<17} {a['user']}: {a['note']}")

print("\nchain intact?     ", il.verify(chain.records, KEY) or "yes")
anchor = chain.anchor()
forged = copy.deepcopy(chain.records)
forged[2]["decision"] = "allow"
print("after editing #3  ", il.verify(forged, KEY)[0])
print("after cutting tail", il.verify(chain.records[:3], KEY, anchor)[0])
