"""Demo: rebuild a compromised session from a tool log, a transcript and a memory file.

    .venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/07-session-reconstruction/demo.py
"""

import tempfile

from aisec_lab import load_lab_module

f = load_lab_module(__file__, "forensics")

with tempfile.TemporaryDirectory() as d:
    f.simulate_session(d, compromised=True)
    r = f.reconstruct(d)
    print("== timeline")
    for ts, kind, line in r.timeline:
        print(f"  t={ts:<3} {kind:10s} {line}")
    print("\nlog integrity ok:", r.log_ok)
    print("injection point : tool-log entry #", r.injection_seq)
    print("first anomaly   : tool-log entry #", r.first_anomaly_seq)
    print("exposed secrets :", r.exposed)
    print("exfiltrated     :", r.exfiltrated)
    print("tainted memory  :", r.tainted_memory)
    print("score / severity:", r.score, r.severity)
    print("actions:")
    for a in r.actions:
        print("  -", a)
