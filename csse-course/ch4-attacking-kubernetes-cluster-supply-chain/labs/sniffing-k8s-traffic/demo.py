"""What a sniffer sees, and what mTLS hides. From repo root:
    .venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/sniffing-k8s-traffic/demo.py
"""
import json
from pathlib import Path

import sniff

FIX = Path(__file__).parent / "fixtures"
flows = sniff.load(FIX / "capture.json")
mesh = json.loads((FIX / "peer-authentication.json").read_text())

print("== before mesh: credentials visible to a sniffer ==")
for e in sniff.find_exposures(flows):
    print(f"  {e.flow:22} {e.kind:15} {e.redacted}")
after = sniff.apply_mesh(flows, mesh)
print("== after PeerAuthentication STRICT ==")
print("  exposures left :", [(e.flow, e.kind) for e in sniff.find_exposures(after)])
print("  still plaintext:", sniff.mtls_gaps(flows, mesh))
print("  metadata still visible:", len(sniff.metadata_visible(flows)), "flows (who talks to whom)")
print("== can a pod sniff? ==")
pod = {"spec": {"hostNetwork": True, "containers": [{"name": "debug", "image": "x"}]}}
print("  default caps + hostNetwork:", sniff.can_sniff(pod))
pod["spec"]["hostNetwork"] = False
pod["spec"]["containers"][0]["securityContext"] = {"capabilities": {"drop": ["ALL"]}}
print("  drop ALL                  :", sniff.can_sniff(pod))
