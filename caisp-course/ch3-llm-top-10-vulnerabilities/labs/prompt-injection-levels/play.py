"""Try your own payloads against the ladder.

    python play.py                 # uses my_payloads.json
    python play.py other.json      # or another file
    python play.py --show-defense  # print what each level does (spoilers: defense names only)

Edit my_payloads.json. Each key is a level number. A value is a string, an object with
"user" and "document" (the document is retrieved text, like a web page or a file), or a
list of those (several turns). Level 8 has no payload that works. Try anyway, then read
the README to see why.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from levels import LEVELS, attempt  # noqa: E402


def main(argv: list[str]) -> int:
    if "--show-defense" in argv:
        for lv in LEVELS:
            print(f"Level {lv.number}: {lv.title} -> {lv.defense}")
        return 0
    path = Path(argv[0]) if argv else Path(__file__).with_name("my_payloads.json")
    payloads = json.loads(path.read_text(encoding="utf-8"))
    solved = 0
    for lv in LEVELS:
        payload = payloads.get(str(lv.number))
        if payload is None:
            print(f"Level {lv.number} ({lv.title}): no payload yet")
            continue
        result = attempt(lv, payload)
        solved += result.leaked
        status = "LEAKED  (level beaten)" if result.leaked else "held    (try again)"
        print(f"Level {lv.number} ({lv.title}): {status} | reply: {result.responses[-1][:60]}")
    print(f"\nBeaten: {solved}/{len(LEVELS)} levels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
