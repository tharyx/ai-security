"""Demo: assess the sample team and print the report, then show partial credit."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dsomm  # noqa: E402

here = Path(__file__).parent
catalog = dsomm.load_yaml(str(here / "activities.yaml"))
answers = dsomm.load_yaml(str(here / "my-org.yaml"))
print(dsomm.render_report(catalog, answers))
print()
a = dsomm.assess(catalog, answers, partial_credit=True)
print("With partial credit:", {k: f"L{r.level}" for k, r in a.dimensions.items()})
a = dsomm.assess(catalog, answers)
for r in a.dimensions.values():
    if r.ahead:
        print(f"Ahead of level in {r.title}:", [x["id"] for x in r.ahead])
