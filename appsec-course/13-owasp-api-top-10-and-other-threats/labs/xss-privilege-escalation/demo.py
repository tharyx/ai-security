import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import xss_privesc as x  # noqa: E402

print("mallory's comment:", x.MALICIOUS_COMMENT)
print()
print(f"{'defences':<26} {'admin cookie stolen':<21} mallory's role after the admin views the page")
for name, d in (("none", {}), ("HttpOnly cookie only", {"httponly": True}), ("CSRF token only", {"csrf": True}),
                ("HttpOnly + CSRF token", {"httponly": True, "csrf": True}), ("strict CSP only", {"csp": True}),
                ("output encoding only", {"encode": True}),
                ("all four", {"encode": True, "httponly": True, "csp": True, "csrf": True})):
    r = x.run_attack(**d)
    print(f"{name:<26} {str(r['cookie_stolen']):<21} {r['mallory_role']}")
