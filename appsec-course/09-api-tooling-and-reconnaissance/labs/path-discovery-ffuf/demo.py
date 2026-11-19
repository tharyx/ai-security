import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ffuflite as f  # noqa: E402

KNOWN = {
    "/api/v1/login": (200, "login form"),
    "/api/v1/products": (200, "product list"),
    "/api/v1/admin": (401, "unauthorized"),
    "/api/v1/debug": (200, "DEBUG MODE ON - leaks config"),
}

print("=== ffuf-style discovery against /api/v1/FUZZ (default: hide 404) ===")
handle = f.make_router(KNOWN)
for hit in f.fuzz("/api/v1/FUZZ", f.DEFAULT_WORDLIST, handle):
    print(f"  {hit.status}  len={hit.length:<3}  {hit.path}")

print("\n=== Same scan, but the API returns 404 for protected paths too ===")
handle2 = f.make_router(KNOWN, hide_unknown=True)
for hit in f.fuzz("/api/v1/FUZZ", f.DEFAULT_WORDLIST, handle2):
    print(f"  {hit.status}  len={hit.length:<3}  {hit.path}")
print("  (the /admin endpoint no longer stands out)")
