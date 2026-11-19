from delegator_worker import make_pair

TASK = """Plan the week
- Summarize public release notes about the framework
- Draft a note for employee Alice about the internal only roadmap
- Check patient record FAKE-SSN-123 against the form
"""
for naive in (True, False):
    d, local, cloud = make_pair(naive=naive)
    res = d.run(TASK)
    print("NAIVE router" if naive else "CLASSIFYING router")
    for r in res:
        print(f"  [{r.classification:<12}] -> {r.location:<5} {r.subtask[:50]}")
    leaked = any("FAKE-SSN-123" in s for s in cloud.seen)
    print(f"  restricted data seen by cloud provider: {leaked}\n")
