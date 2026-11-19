"""Demo: session fixation and state tampering against vulnerable vs secure session handling."""
import base64
import json

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "acp_session")

print("== VULNERABLE ==")
v = m.VulnerableSessions()
v.precreate("sess-attacker")                      # attacker plants a known id
v.login("admin-agent", "FAKE-s2", "sess-attacker")  # victim admin is lured into using it
print("fixation:", v.call("sess-attacker", "wire_funds"))
low = v.login("report-agent", "FAKE-s1")
blob = json.loads(base64.b64decode(v.export_state(low)))
blob["role"] = "admin"
forged = v.resume(base64.b64encode(json.dumps(blob).encode()).decode())
print("tampered state:", v.call(forged, "wire_funds"))

print("== SECURE ==")
s = m.SecureSessions(key=b"FAKE-demo-key")
s.precreate("sess-attacker")
admin = s.login("admin-agent", "FAKE-s2", "sess-attacker")
print("admin session id is random:", admin != "sess-attacker")
try:
    s.call("sess-attacker", "wire_funds")
except m.AccessDenied as e:
    print("fixation:", e)
low = s.login("report-agent", "FAKE-s1")
tok = s.export_state(low)
b64, sig = tok.rsplit(".", 1)
body = json.loads(base64.b64decode(b64))
body["agent"] = "admin-agent"
try:
    s.resume(base64.b64encode(json.dumps(body, sort_keys=True).encode()).decode() + "." + sig, "report-agent")
except m.AccessDenied as e:
    print("tampered state:", e)
