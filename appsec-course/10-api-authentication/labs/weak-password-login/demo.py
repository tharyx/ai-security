import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import weak_login as w  # noqa: E402

USERS = {"carol": "p@ssw0rd"}  # toy lab password

print("attacker wordlist:", w.ATTACK_WORDLIST)
print("\n=== Open login (no lockout, no rate limit) ===")
print(" ", w.dictionary_attack(w.OpenLogin(USERS), "carol", w.ATTACK_WORDLIST))

print("\n=== Guarded login: lockout after 5 failures ===")
print(" ", w.dictionary_attack(w.GuardedLogin(USERS, max_failures=5, burst=100),
                               "carol", w.ATTACK_WORDLIST))

print("\n=== Guarded login: per-IP rate limit (burst 3, 1 req/s) ===")
print(" ", w.dictionary_attack(w.GuardedLogin(USERS, max_failures=100, burst=3),
                               "carol", w.ATTACK_WORDLIST))
