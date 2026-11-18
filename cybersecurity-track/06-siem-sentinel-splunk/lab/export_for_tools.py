"""Write queries/events.csv (for Splunk) and queries/events_datatable.kql (for KQL).

Run:  python cybersecurity-track/06-siem-sentinel-splunk/lab/export_for_tools.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import minisiem  # noqa: E402

OUT = Path(__file__).resolve().parent / "queries"


def main() -> None:
    events = minisiem.ingest()
    OUT.mkdir(exist_ok=True)
    minisiem.export_csv(events, OUT / "events.csv")
    (OUT / "events_datatable.kql").write_text(minisiem.export_kql_datatable(events), encoding="utf-8")
    print(f"wrote {len(events)} events to events.csv and events_datatable.kql")


if __name__ == "__main__":
    main()
