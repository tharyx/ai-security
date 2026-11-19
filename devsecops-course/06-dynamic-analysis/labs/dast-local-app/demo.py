import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # allow running from anywhere
from aisec_lab import load_lab_module  # noqa: E402

app = load_lab_module(__file__, "vulnapp")
prober = load_lab_module(__file__, "prober")

for label, fixed in (("WEAK app", False), ("FIXED app", True)):
    with app.running(fixed) as srv:
        p = prober.Prober(srv.base)
        # URLs a QA person would know; a spider alone would miss the JS-only pages
        found = p.scan(["/search?q=", "/user?id="])
        print(f"== {label}: {len(found)} finding(s), {p.requests_sent} requests ==")
        for f in found:
            print(f"  [{f.severity:6}] {f.rule:17} {f.url.replace(srv.base, '')}  ({f.evidence})")
