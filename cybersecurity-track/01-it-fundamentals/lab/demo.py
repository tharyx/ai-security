"""Run the log analyzer on the synthetic Windows + Linux logs.

    .venv/Scripts/python cybersecurity-track/01-it-fundamentals/lab/demo.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import log_analyzer as la  # noqa: E402
import sample_data as sd   # noqa: E402


def main() -> None:
    events = la.parse_windows_events(sd.WINDOWS_JSON) + la.parse_auth_log(sd.AUTH_LOG)
    print(f"parsed {len(events)} events "
          f"({sum(e.os == 'windows' for e in events)} windows, {sum(e.os == 'linux' for e in events)} linux)\n")
    print(f"{'severity':<9} {'rule':<20} {'host':<20} summary")
    print("-" * 110)
    for f in la.analyze(events):
        print(f"{f.severity:<9} {f.rule:<20} {f.host:<20} {f.summary}")


if __name__ == "__main__":
    main()
