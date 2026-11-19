import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from aisec_lab import load_lab_module  # noqa: E402

api = load_lab_module(__file__, "mockapi")
scan = load_lab_module(__file__, "apiscan")
spec = scan.load_spec(Path(__file__).parent / "fixtures" / "openapi.yaml")

print("operations found in the spec:")
for ep in scan.endpoints(spec):
    print(f"  {ep.method:5} {ep.path:26} secured={ep.secured} params={[p[0] for p in ep.params]}")
    for label, kind, _, _ in scan.generate_requests(ep):
        print(f"        test: {label}")

for label, fixed in (("WEAK API", False), ("FIXED API", True)):
    with api.running(fixed) as srv:
        found, sent = scan.scan(spec, srv.base, {"user": "alice", "password": "alice-demo-pass"}, {"orderId": 2})
    print(f"\n== {label}: {len(found)} finding(s), {sent} requests ==")
    for f in found:
        print(f"  [{f.severity:6}] {f.rule:17} {f.endpoint:26} {f.evidence}")
