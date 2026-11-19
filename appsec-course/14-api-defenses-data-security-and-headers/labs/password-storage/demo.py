import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pwstore as p  # noqa: E402

LAB_USERS = {"asha": "monsoon2024", "ravi": "letmein", "meena": "monsoon2024", "joe": "correct horse battery staple"}

print("1. Legacy table: unsalted MD5")
legacy = {u: p.md5_unsalted(pw) for u, pw in LAB_USERS.items()}
for u, h in legacy.items():
    print(f"   {u:6} {h}")
print("   users sharing a password (no cracking needed):", p.identical_hash_groups(legacy))
cracked, guesses, secs = p.dictionary_attack(legacy, p.LAB_WORDLIST)
print(f"   dictionary attack: cracked {sorted(cracked.items())} in {guesses} guesses, {secs * 1000:.1f} ms")

print("\n2. Modern table: PBKDF2-HMAC-SHA256, random salt per user (lab uses 20,000 iterations; policy is",
      f"{p.PBKDF2_POLICY_ITERATIONS:,})")
modern = {u: p.pbkdf2_hash(pw, iterations=20_000) for u, pw in LAB_USERS.items()}
for u, h in modern.items():
    print(f"   {u:6} {h[:60]}...")
print("   users sharing a password:", p.identical_hash_groups(modern))
cracked, guesses, secs = p.dictionary_attack(modern, p.LAB_WORDLIST)
print(f"   dictionary attack: cracked {sorted(cracked.items())} in {guesses} guesses, {secs * 1000:.1f} ms")
print("   (weak passwords still fall to a dictionary; slow hashing buys time, the blocklist removes the weak ones)")

print("\n3. Pepper: the DB alone is not enough")
pepper = p.make_fake_pepper()
peppered = {u: p.pbkdf2_hash(pw, iterations=20_000, pepper=pepper) for u, pw in LAB_USERS.items()}
cracked, _, _ = p.dictionary_attack(peppered, p.LAB_WORDLIST, pepper=None)
print("   attacker without pepper cracked:", cracked)

print("\n4. Upgrade on login (legacy MD5 -> PBKDF2)")
store = p.UserStore(iterations=20_000)
store.users = dict(legacy)
print("   ravi logs in:", store.login("ravi", "letmein"), "| stored now:", store.users["ravi"][:40] + "...")
print("   upgraded users:", store.upgraded, "| asha still legacy:", store.users["asha"].startswith("$md5$"))

print("\n5. Password policy (NIST SP 800-63B-4 style)")
for pw, mfa in [("Tr0ub4dor&3", False), ("Tr0ub4dor&3", True), ("password123", True),
                ("correct horse battery staple", False)]:
    print(f"   {pw!r:32} mfa={mfa!s:5} -> {p.check_password_policy(pw, mfa) or 'OK'}")
