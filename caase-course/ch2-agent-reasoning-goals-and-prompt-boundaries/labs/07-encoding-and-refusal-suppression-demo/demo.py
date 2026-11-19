"""Demo: hidden and translated injections, refusal suppression, naive vs normalising detector.

    .venv/Scripts/python caase-course/ch2-agent-reasoning-goals-and-prompt-boundaries/labs/07-encoding-and-refusal-suppression-demo/demo.py
"""

from aisec_lab import load_lab_module

e = load_lab_module(__file__, "encodings")

print(f"{'variant':24s} {'naive':6s} normalising detector")
for name, text in {**e.VARIANTS, "refusal suppression": e.SUPPRESSION}.items():
    print(f"{name:24s} {str(e.naive_detect(text)):6s} {e.detect(text) or 'MISSED'}")
