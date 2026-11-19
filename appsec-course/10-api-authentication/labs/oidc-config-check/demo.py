import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import oidccheck as o  # noqa: E402

ISS = "https://login.lab.example"
for name in ("discovery_insecure.json", "discovery_secure.json"):
    findings = o.check_discovery(o.load(HERE / "fixtures" / name), ISS)
    print(f"=== {name}: {len(findings)} finding(s), gate exit {o.gate(findings)} ===")
    for f in findings:
        print(f"  [{f.severity:<8}] {f.rule:<22} {f.detail}")
    print()

print("=== ID token claim checks ===")
good = {"iss": ISS, "aud": "shop-spa", "exp": 2000, "nonce": "n-123"}
for label, claims in [("valid", good),
                      ("other client", dict(good, aud="other-app")),
                      ("replayed + expired", dict(good, nonce="old", exp=500))]:
    print(f"  {label:<20} -> {o.validate_id_token_claims(claims, issuer=ISS, client_id='shop-spa', nonce='n-123', now=1000)}")
