"""Demo: audit the insecure and the hardened simulated gateway."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auditor  # noqa: E402
import sim_gateway as g  # noqa: E402

for label, cfg in (("INSECURE", g.INSECURE_CONFIG), ("HARDENED", g.HARDENED_CONFIG)):
    print(f"== {label} ==")
    print("static findings:")
    for f in auditor.audit_config(cfg) or [{"id": "none", "message": "clean"}]:
        print(f"  [{f.get('severity', '-')}] {f['id']}: {f['message']}")
    with g.SimGateway(cfg) as gw:
        print("live probes (loopback, ephemeral port):")
        for f in auditor.probe_gateway(gw.port) or [{"id": "none", "message": "clean"}]:
            print(f"  [{f.get('severity', '-')}] {f['id']}: {f['message']}")
    print()
