import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app  # noqa: E402
import dast  # noqa: E402

for label, fixed in (("vulnerable app", False), ("fixed app", True)):
    srv, base = app.start(fixed=fixed)
    try:
        print(f"== {label} (listening on 127.0.0.1 only) ==")
        print("crawl found:", {p: sorted(v) for p, v in sorted(dast.crawl(base).items())})
        findings = dast.scan(base)
        for f in findings:
            print(f"  {f.kind:15} {f.path:8} param={f.param:4} {f.evidence}")
        if not findings:
            print("  no findings")
    finally:
        srv.shutdown()
        srv.server_close()
