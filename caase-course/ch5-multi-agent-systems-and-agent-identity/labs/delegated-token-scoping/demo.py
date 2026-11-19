from delegation_tokens import TokenError, TokenService, act_chain

T0 = 1000.0
s = TokenService()
root = s.issue_root("alice", "orchestrator", "agent-b", ["calendar.read", "mail.send", "files.read"], 600, T0)
t2 = s.exchange(root, new_agent="agent-b", aud="calendar-api", scopes=["calendar.read", "mail.send"], ttl=300, now=T0 + 1)
t3 = s.exchange(t2, new_agent="agent-c", aud="calendar-api", scopes=["calendar.read"], ttl=300, now=T0 + 2)
for name, t in (("root", root), ("hop-2", t2), ("hop-3", t3)):
    c = s.decode(t)
    print(f"{name:<6} sub={c['sub']:<12} aud={c['aud']:<13} scope={c['scope']} exp={c['exp']} chain={act_chain(c)}")

def attempt(label, fn):
    try:
        fn()
        print(f"{label:<34} -> allowed")
    except TokenError as e:
        print(f"{label:<34} -> denied: {e}")

attempt("hop-3 token reads calendar", lambda: s.verify(t3, audience="calendar-api", scope="calendar.read", now=T0 + 3))
attempt("hop-3 token sends mail", lambda: s.verify(t3, audience="calendar-api", scope="mail.send", now=T0 + 3))
attempt("hop-3 token used at mail-api", lambda: s.verify(t3, audience="mail-api", scope="calendar.read", now=T0 + 3))
attempt("hop-3 token after expiry", lambda: s.verify(t3, audience="calendar-api", scope="calendar.read", now=T0 + 700))
attempt("hop-3 tries to widen scope", lambda: s.exchange(t3, new_agent="d", aud="x", scopes=["mail.send"], ttl=5, now=T0 + 3))
