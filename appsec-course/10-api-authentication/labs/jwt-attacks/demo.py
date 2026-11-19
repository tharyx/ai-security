import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import jwtlab as j  # noqa: E402

STRONG = "FAKE-" + "9f3c2a7b61e04d58" + "-DEMO"
AUD = "shop-api"
now = int(time.time())

good = j.encode_hs256({"sub": "alice", "role": "user", "aud": AUD, "exp": now + 3600}, STRONG)
print("=== A valid HS256 token ===")
print(" ", good)
print("  strict verify:", j.verify_strict(good, STRONG, audience=AUD))

print("\n=== Attack: alg:none ===")
forged = j.forge_alg_none({"sub": "attacker", "role": "admin", "aud": AUD, "exp": now + 3600})
print("  naive verifier ->", j.verify_naive(forged, STRONG))
try:
    j.verify_strict(forged, STRONG, audience=AUD)
except ValueError as e:
    print("  strict verifier -> REJECTED:", e)

print("\n=== Attack: weak secret cracking ===")
weak = j.make_fake_weak_secret()
wtok = j.encode_hs256({"sub": "bob", "aud": AUD, "exp": now + 60}, weak)
print("  wordlist:", j.TINY_WORDLIST)
print("  cracked secret ->", j.crack_hs256_secret(wtok, j.TINY_WORDLIST))
print("  strong token crackable? ->", j.crack_hs256_secret(good, j.TINY_WORDLIST))

print("\n=== Attack: missing/expired claims ===")
noexp = j.encode_hs256({"sub": "alice", "aud": AUD}, STRONG)
expired = j.encode_hs256({"sub": "alice", "aud": AUD, "exp": now - 10}, STRONG)
for name, tok in [("no exp", noexp), ("expired", expired)]:
    try:
        j.verify_strict(tok, STRONG, audience=AUD)
    except ValueError as e:
        print(f"  {name:8} -> REJECTED: {e}")

print("\n=== Attack: kid path traversal ===")
key_dir = {"main": STRONG, "../../public/keys/pub": "public"}
print("  vulnerable resolver(kid='../../public/keys/pub') ->",
      repr(j.resolve_key_vulnerable("../../public/keys/pub", key_dir)))
try:
    j.resolve_key_safe("../../public/keys/pub", key_dir)
except ValueError as e:
    print("  safe resolver -> REJECTED:", e)
