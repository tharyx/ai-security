"""Demo: a three-tool chain turns a low-privilege agent into an admin-maker; static closure shows it in advance.

    .venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/04-tool-chain-escalation/demo.py
"""

from aisec_lab import load_lab_module

c = load_lab_module(__file__, "chain_escalation")

granted = {"fs:read", "tickets:read", "tickets:write"}
have, steps = c.effective_privilege(granted)
print("granted:", sorted(granted))
print("effective (by chaining):", sorted(have))
print("derivation:", steps)

for label, kw in (("VULNERABLE", {}),
                  ("DEFENDED", dict(redact_secrets=True, identity_authz=True,
                                    path_allowlist=("notes.txt",), chain_gate=True))):
    p = c.Platform()
    a = c.Agent(c.ChainLLM(), p, **kw)
    a.run("Please triage ticket 7")
    print(f"== {label}: mallory role = {p.roles['mallory']!r}; trace = {a.trace}")
