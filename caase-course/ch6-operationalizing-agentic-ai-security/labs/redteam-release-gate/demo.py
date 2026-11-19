import release_gate as g
from agent_under_test import Agent

for name, factory in (("vulnerable", lambda: Agent(hardened=False)), ("hardened", lambda: Agent(hardened=True))):
    res = g.evaluate(factory, g.SUITE, g.Policy())
    print(f"== {name}: gate {'PASS' if res.passed else 'FAIL (build broken)'}  ASR={res.asr:.0%}")
    for atk in g.SUITE:
        mark = "SUCCEEDED" if res.outcomes[atk.id] else "blocked"
        print(f"   {atk.id} {atk.category:<19} {atk.severity:<8} {mark}")
    for r in res.reasons:
        print("   BLOCKING:", r)
