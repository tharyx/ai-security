import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gates as g  # noqa: E402

FX = HERE / "fixtures"
KEV = set(json.loads((FX / "kev.json").read_text())["kev"])
BASELINE = json.loads((FX / "baseline.json").read_text())["suppressions"]


def load(d, name):
    return json.loads((FX / d / name).read_text())


for label, d in [("BEFORE the fixes", "reports-before"), ("AFTER the fixes", "reports-after")]:
    findings = (g.parse_sca(load(d, "sca-osv.json"), KEV) + g.parse_sarif(load(d, "sast.sarif"))
                + g.parse_zap(load(d, "zap-report.json")))
    code, lines = g.evaluate(findings, baseline=BASELINE)
    print(f"== {label}: {len(findings)} findings, gate exit {code}")
    for line in lines:
        print("  ", line)
    print()

print("== Embedded in the pipeline (reports-before), branch main")
runner = g.embed_in_pipeline(FX / "reports-before", BASELINE, KEV)
defn = runner.load(FX / "secure-pipeline.json")
print(runner.run(defn, branch="main").summary())
print("\n== Embedded in the pipeline (reports-after), branch main")
runner = g.embed_in_pipeline(FX / "reports-after", BASELINE, KEV)
r = runner.run(defn, branch="main")
print(r.summary())
print("   sca job artifact:", list(r.jobs["sca"].artifacts))
