import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import openapi_recon as r  # noqa: E402

spec = r.load_spec(HERE / "fixtures" / "openapi.json")
live = [
    ("POST", "/api/v1/login"),
    ("GET", "/api/v1/products"),
    ("GET", "/api/v1/admin/users"),
    ("GET", "/api/v1/debug/env"),   # undocumented (shadow)
]
print(r.report(spec, live))
