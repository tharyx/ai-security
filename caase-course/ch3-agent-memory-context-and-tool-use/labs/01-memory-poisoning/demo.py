"""Demo: a web page poisons long-term memory; a later session pays the attacker. Then the defended store.

    .venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/01-memory-poisoning/demo.py
"""

import tempfile
from pathlib import Path

from aisec_lab import load_lab_module

m = load_lab_module(__file__, "memory")

for label, cls in (("VULNERABLE store", m.VulnerableStore), ("PROVENANCE store", m.ProvenanceStore)):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "memory.json"
        s1, s2 = m.Agent(cls(p), "session-1"), m.Agent(cls(p), "session-2")
        s1.say("Summarize https://blog.example/post")
        print(f"== {label}")
        print("  session 2 says:", s2.say("pay invoice 42"))
        if cls is m.ProvenanceStore:
            for e in s1.store.quarantined():
                print(f"  quarantined: {e.key}={e.value} source={e.source} trusted={e.trusted}")
