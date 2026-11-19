import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resolver as r  # noqa: E402

idx, lock = r.build_fixture()
pkg = "acme-billing-utils"
rows = [
    ("highest-version (vulnerable)", r.resolve_highest_version(pkg, idx)),
    ("pinned index", r.resolve_pinned_index(pkg, idx, {pkg: "private"})),
    ("reserved prefix 'acme-'", r.resolve_reserved_prefix(pkg, idx, ("acme-",))),
    ("hash-locked", r.resolve_with_lock(pkg, idx, lock)),
]
for name, res in rows:
    sink: list[str] = []
    r.install(res, idx, sink)
    print(f"{name:30} -> {res.version} from {res.index:8} canary_ran={bool(sink)}  ({res.reason})")
print("IDE quick fix:", r.ide_quick_fix(pkg, idx))
