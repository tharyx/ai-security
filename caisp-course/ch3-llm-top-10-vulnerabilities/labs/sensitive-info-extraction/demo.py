"""Run the six extraction techniques against the leaky and the hardened assistant.

    python caisp-course/ch3-llm-top-10-vulnerabilities/labs/sensitive-info-extraction/demo.py
"""

from __future__ import annotations

from assistant import CANARIES, HardenedAssistant, LeakyAssistant
from techniques import TECHNIQUES

print(f"{'Technique':<32}{'Leaky assistant leaks':<34}Hardened leaks")
for name, question in TECHNIQUES:
    leaky = LeakyAssistant().ask("alice", question)
    hard = HardenedAssistant().ask("alice", question)
    l1 = ", ".join(n for n, v in CANARIES.items() if v in leaky) or "nothing"
    l2 = ", ".join(n for n, v in CANARIES.items() if v in hard) or "nothing"
    print(f"{name:<32}{l1:<34}{l2}")
