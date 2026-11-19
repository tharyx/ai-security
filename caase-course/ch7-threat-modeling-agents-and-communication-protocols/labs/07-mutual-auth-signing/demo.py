"""Demo: mutual auth + signed messages for each protocol label, replay, cross-protocol replay and a downgrade."""
from aisec_lab import load_lab_module

sc = load_lab_module(__file__, "secure_channel")

try:
    a, b = sc.make_ed25519_pair()
    kind = "ed25519 (cryptography installed)"
except ImportError:
    a, b = sc.make_hmac_pair()
    kind = "hmac-sha256 (cryptography not installed)"
print("Suite family:", kind)

sessions = {}
for proto in sc.PROTOCOLS:
    ca, sb = sc.connect(a, b, proto)
    sessions[proto] = (ca, sb)
    body = sb.receive(ca.send({"hello": proto}))
    print(f"{proto}: suite={ca.suite} sid={ca.sid} delivered={body}")

ca, sb = sessions["a2a"]
env = ca.send({"task": "pay"})
sb.receive(env)
for label, fn in (("replay same envelope", lambda: sb.receive(env)),
                  ("replay A2A envelope into UCP session", lambda: sessions["ucp"][1].receive(env))):
    try:
        fn()
    except sc.MessageError as e:
        print(f"{label}: refused ({e})")

x, y = sc.make_hmac_pair(floor="none")
try:
    sc.connect(*sc.make_hmac_pair(), "a2a", mitm=sc.Mitm(strip_to=["none"]))
except sc.HandshakeError as e:
    print("MITM strips strong suites, floor=hmac:", e)
cs, ss = sc.connect(x, y, "a2a", mitm=sc.Mitm(strip_to=["none"]))
print("Legacy peers with floor=none are downgraded to:", cs.suite, "(no authentication at all)")
