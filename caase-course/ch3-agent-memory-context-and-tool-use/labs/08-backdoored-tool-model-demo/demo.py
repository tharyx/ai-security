"""Demo: a toy backdoored model proposes an exfil tool call on a trigger; gates and probing.

    .venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/08-backdoored-tool-model-demo/demo.py
"""

from aisec_lab import load_lab_module

b = load_lab_module(__file__, "backdoor")
model = b.BackdooredToolModel()

print("normal task      ->", model.complete([{"role": "user", "content": "summarize the report"}]))
print("triggered task   ->", model.complete([{"role": "user", "content": f"summarize the report {b.TRIGGER}"}])[:90], "...")

for label, ex in (("no gate", b.GatedExecutor({"read_file", "http_post"}, ("collector.example",))),
                  ("task allowlist", b.GatedExecutor({"read_file"}))):
    b.run_task(b.BackdooredToolModel(), f"summarize the report {b.TRIGGER}", ex)
    print(f"{label:15s}  -> sent_out={len(ex.sent)} denied={ex.denied}")

print("probe (guessed trigger)  :", b.probe_for_triggers(model, ["summarize the report"], ["hello", b.TRIGGER]))
print("probe (unguessed trigger):", b.probe_for_triggers(model, ["summarize the report"], ["hello", "|OTHER|"]))
