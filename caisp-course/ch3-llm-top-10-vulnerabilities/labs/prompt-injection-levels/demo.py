"""Run the reference solutions against the ladder and show which level each one beats.

    python caisp-course/ch3-llm-top-10-vulnerabilities/labs/prompt-injection-levels/demo.py
"""

from __future__ import annotations

import json
from pathlib import Path

from levels import LEVELS, attempt

solutions = json.loads(Path(__file__).with_name("solutions.json").read_text(encoding="utf-8"))

print(f"{'Level':<6}{'Defense':<44}{'Own solution':<14}{'Previous solution'}")
for lv in LEVELS:
    own = attempt(lv, solutions[str(lv.number)]) if str(lv.number) in solutions else None
    prev = attempt(lv, solutions[str(lv.number - 1)]) if str(lv.number - 1) in solutions else None
    own_s = "-" if own is None else ("LEAKS" if own.leaked else "held")
    prev_s = "-" if prev is None else ("LEAKS" if prev.leaked else "held")
    print(f"{lv.number:<6}{lv.title:<44}{own_s:<14}{prev_s}")

print("\nLevel 8 held against every payload above. The secret is not in the model's context.")
bot = LEVELS[7].build()
print("Server-side check of a wrong code :", bot.verify("guess"))
print("Server-side check of the real code:", bot.verify(LEVELS[7].secret))
