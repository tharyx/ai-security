import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cors_lab as c  # noqa: E402

ATTACKERS = ["https://evil.example", "null", "https://evilbank.example", "https://bank.example.evil.net"]
print("Can a script on the attacker origin read alice's account with her cookie?")
print(f"{'policy':<9}" + "".join(f"{a:<31}" for a in ATTACKERS))
for policy in ("reflect", "null", "suffix", "prefix", "wildcard", "secure"):
    row = []
    for a in ATTACKERS:
        body = c.browser_cross_origin_read(a, policy)
        row.append("READS balance + key" if body and "balance" in body else "blocked")
    print(f"{policy:<9}" + "".join(f"{r:<31}" for r in row))
print()
print("legit https://app.bank.example, secure policy:", c.browser_cross_origin_read("https://app.bank.example", "secure"))
print("CORS is not CSRF protection: a form POST reaches the server without preflight?",
      c.simple_post_reaches_server("application/x-www-form-urlencoded"))
