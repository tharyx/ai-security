"""Start the mock Trivy server on 127.0.0.1, scan via the client, gate the result. From repo root:
    .venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/trivy-apis/demo.py
"""
import importlib.util
import json
import sys
from pathlib import Path

import trivy_mock_api as api

# reuse the parser from the sibling lab
p = Path(__file__).resolve().parents[1] / "trivy-vuln-scan" / "trivy_report.py"
spec = importlib.util.spec_from_file_location("trivy_report_shared", p)
tr = importlib.util.module_from_spec(spec)
sys.modules["trivy_report_shared"] = tr
spec.loader.exec_module(tr)

rep = json.loads((p.parent / "fixtures" / "trivy-report.json").read_text())
TOKEN = "demo-token-not-secret"
srv = api.make_server({rep["ArtifactName"]: rep}, TOKEN)
api.serve_in_thread(srv)
base = f"http://127.0.0.1:{srv.server_address[1]}"
print("server on 127.0.0.1 (port chosen at runtime)")
print("no token     ->", api.scan(base, rep["ArtifactName"], "")[0])
print("unknown img  ->", api.scan(base, "nope:1", TOKEN)[0])
code, body = api.scan(base, rep["ArtifactName"], TOKEN)
print("valid scan   ->", code, tr.summary(body))
ok, why = tr.gate(body, fail_on="CRITICAL")
print("CI gate (CRITICAL):", "PASS" if ok else "FAIL", len(why), "reasons")
srv.shutdown()
