import json
from pathlib import Path

import trace_dashboard as d

here = Path(__file__).parent
baseline, drifted = d.sample_baseline(), d.sample_drifted()
(here / "sample_traces.json").write_text(json.dumps({"traces": baseline + drifted}, indent=1), encoding="utf-8")

traces = d.load((here / "sample_traces.json").read_text(encoding="utf-8"))
profile = d.build_profile(traces[: len(baseline)])
findings = d.detect(traces[len(baseline):], profile)
for f in findings:
    print(f"[{f.rule}] {f.scope}: {f.detail}")
(here / "dashboard.md").write_text(d.render_markdown(traces[-3:], findings), encoding="utf-8")
(here / "dashboard.html").write_text(d.render_html(traces[-3:], findings), encoding="utf-8")
print("wrote dashboard.md and dashboard.html (open the HTML in a browser)")
