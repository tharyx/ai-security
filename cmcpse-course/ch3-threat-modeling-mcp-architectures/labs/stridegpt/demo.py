"""Demo: offline STRIDE GPT twin, then validate its output against the manual STRIDE findings."""

import json

from aisec_lab import MockLLM, load_lab_module

sg = load_lab_module(__file__, "stridegpt_offline")
sm = sg.sm

arch = sm.load_arch()
print("Prompt preview:", sg.build_prompt(arch["description"])[:160].replace("\n", " | "), "...\n")
for llm, label in ((None, "template generator"), (MockLLM(), "MockLLM then fallback")):
    out = sg.generate(arch["description"] + " It has a database.", llm)
    print(f"{label}: source={out['source']}, {len(out['threats'])} threats")
print()
result = sg.generate(arch["description"] + " It has a database.")
report = sg.validate(result["threats"], sm.find_threats(arch), json.dumps(arch))
print(sg.render_report(report))
