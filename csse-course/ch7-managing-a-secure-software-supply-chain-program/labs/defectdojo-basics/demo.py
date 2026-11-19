import json
import pathlib

import dojo_model as dm

fx = pathlib.Path(__file__).parent / "fixtures"
load = lambda n: json.loads((fx / n).read_text())  # noqa: E731

d = dm.Dojo(dedupe_scope="product")
prod = d.add_product("example-app")
eng = d.add_engagement(prod, "release-1.0")
t_sast = d.add_test(eng, "SARIF")
t_sca = d.add_test(eng, "Trivy Scan")

print("SARIF import      :", d.import_scan(t_sast, "SARIF", load("sast.sarif.json")))
print("Trivy import      :", d.import_scan(t_sca, "Trivy Scan", load("trivy-fs.json")))
print("Trivy import again:", d.import_scan(t_sca, "Trivy Scan", load("trivy-fs.json")))
print("open by severity  :", d.counts_by_severity(prod))

t2 = d.add_test(d.add_engagement(prod, "nightly"), "Trivy Scan")
print("new engagement    :", d.import_scan(t2, "Trivy Scan", load("trivy-fs.json")), "(product-wide dedup)")

print("reimport after fix:", d.reimport_scan(t_sca, "Trivy Scan", load("trivy-fs-rescan.json")))
print("open by severity  :", d.counts_by_severity(prod))
for f in t_sca.findings:
    print(f"  {f.title:28} active={f.active!s:5} dup={f.duplicate!s:5} mitigated={f.is_mitigated}")
