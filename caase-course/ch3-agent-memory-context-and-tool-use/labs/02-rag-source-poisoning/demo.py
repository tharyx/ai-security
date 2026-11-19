"""Demo: a poisoned RAG source rewrites later answers; trust weighting and quarantine stop it.

    .venv/Scripts/python caase-course/ch3-agent-memory-context-and-tool-use/labs/02-rag-source-poisoning/demo.py
"""

from aisec_lab import load_lab_module

r = load_lab_module(__file__, "rag_poison")
Q = "What is the refund policy?"

for label, defended in (("VULNERABLE index", False), ("DEFENDED index", True)):
    a = r.build(defended)
    print(f"== {label}")
    print("  before poison:", a.answer(Q))
    ingested = a.index.ingest(r.POISON)
    print("  poison ingested:", ingested, [(d.doc_id, why) for d, why in a.index.quarantined])
    print("  after poison: ", a.answer(Q))
