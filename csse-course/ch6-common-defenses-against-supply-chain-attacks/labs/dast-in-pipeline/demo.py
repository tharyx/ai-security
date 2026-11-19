"""Demo: start local servers on 127.0.0.1, scan them, stop them."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dast_stage as d  # noqa: E402

for label, handler in (("weak app", d.WeakApp), ("hardened app", d.HardenedApp)):
    srv, base = d.start_server(handler)
    try:
        f = d.scan(base)
        print(f"== {label}: gate {d.gate(f)} ({len(f)} findings)")
        for x in f:
            print(f"   [{x['severity']:6}] {x['id']:24} {x['detail'][:70]}")
    finally:
        d.stop_server(srv)
try:
    d.scan("http://app.example")
except PermissionError as e:
    print("scope guard:", e)
