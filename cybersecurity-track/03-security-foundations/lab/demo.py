"""Demo: password storage (wrong vs right) and the phishing header analyzer.

Run from the repo root:
    .venv/Scripts/python cybersecurity-track/03-security-foundations/lab/demo.py
"""

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import password_storage as ps  # noqa: E402
import phishing_analyzer as pa  # noqa: E402

wordlist = ps.load_wordlist((HERE / "samples" / "wordlist.txt").read_text())

# Synthetic users. Two of them reuse the same weak password.
USERS = {"asha": "welcome1", "ben": "welcome1", "chen": "Tr0ub4dor&3-synthetic", "dina": "dragon"}

print("=== Part 1: password storage ===")
print("Stored value for user 'asha' (password 'welcome1'):")
plain = [ps.store_plain(u, p) for u, p in USERS.items()]
md5 = [ps.store_md5(u, p) for u, p in USERS.items()]
pbk = [ps.store_pbkdf2(u, p) for u, p in USERS.items()]
print(f"  plain : {plain[0].stored}")
print(f"  md5   : {md5[0].stored}")
print(f"  pbkdf2: {pbk[0].stored[:32]}...  (salt {pbk[0].salt[:8]}..., {pbk[0].iterations} iterations)")
print("Users with the same stored value (leaks 'same password'):")
print(f"  md5   : {ps.duplicate_hashes(md5)}")
print(f"  pbkdf2: {ps.duplicate_hashes(pbk)}")

print("\n=== Part 2: dictionary attack (stolen table, 15-word list) ===")
print(f"{'scheme':8} {'cracked':8} {'hashes computed':16} {'seconds':8}")
for name, recs in (("plain", plain), ("md5", md5), ("pbkdf2", pbk)):
    t0 = time.perf_counter()
    res = ps.dictionary_attack(recs, wordlist)
    dt = time.perf_counter() - t0
    print(f"{name:8} {len(res['cracked']):>3}/{len(recs):<4} {res['hashes_computed']:<16} {dt:<8.2f}")
res = ps.md5_precomputed_attack(md5, wordlist)
print(f"md5 with a reusable precomputed table: {len(res['cracked'])}/4 cracked, "
      f"only {res['hashes_computed']} hashes computed")

print("\n=== Part 3: phishing header analyzer ===")
for name in ("legit.eml", "phish_spoof.eml", "phish_lookalike.eml"):
    print(f"\n--- {name} ---")
    print(pa.format_report(pa.analyze((HERE / "samples" / name).read_text())))
