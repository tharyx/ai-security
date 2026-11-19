import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import oauth_sim as o  # noqa: E402

CB = "https://app.lab.example"


def setup(secure):
    a = o.AuthServer(secure=secure)
    a.register(o.Client("spa", [CB]))
    return a


print("== 1. Happy path: authorization code + PKCE (secure AS) ==")
a = setup(True)
verifier, challenge = o.pkce_pair()
url = a.authorize("alice", {"client_id": "spa", "redirect_uri": CB, "response_type": "code", "scope": "openid trips:read",
                            "state": "s-123", "nonce": "n-9", "code_challenge": challenge, "code_challenge_method": "S256"})
code = o.client_callback(url, "s-123")
tokens = a.token({"grant_type": "authorization_code", "code": code, "client_id": "spa", "redirect_uri": CB,
                  "code_verifier": verifier})
print("token response keys:", sorted(tokens))
for name in ("access_token", "id_token"):
    h, c = o.jwt_parts(tokens[name])
    print(f"  {name}: typ={h['typ']} aud={c['aud']}")
print("API accepts access token:", o.api_accepts(tokens["access_token"], a.key, True, "trips:read"))
print("API accepts ID token    :", o.api_accepts(tokens["id_token"], a.key, True))

print("\n== 2. Attacks: vulnerable AS vs secure AS ==")
for secure in (False, True):
    a = setup(secure)
    label = "SECURE" if secure else "VULN  "
    # 2a redirect_uri prefix trick
    evil = CB + ".evil.example/steal"
    try:
        a.authorize("alice", {"client_id": "spa", "redirect_uri": evil, "response_type": "code"})
        r1 = "code sent to attacker host " + urlparse(evil).hostname
    except ValueError as e:
        r1 = "blocked: " + str(e)
    # 2b stolen code without verifier
    v, ch = o.pkce_pair()
    u = a.authorize("alice", {"client_id": "spa", "redirect_uri": CB, "response_type": "code",
                              "code_challenge": ch, "code_challenge_method": "S256"})
    stolen = parse_qs(urlparse(u).query)["code"][0]
    try:
        a.token({"grant_type": "authorization_code", "code": stolen, "client_id": "spa", "redirect_uri": CB})
        r2 = "attacker redeemed stolen code"
    except ValueError as e:
        r2 = "blocked: " + str(e)
    # 2c implicit grant
    try:
        a.authorize("alice", {"client_id": "spa", "redirect_uri": CB, "response_type": "token"})
        r3 = "access token returned in URL fragment"
    except ValueError as e:
        r3 = "blocked: " + str(e)
    print(f"[{label}] open redirect_uri : {r1}")
    print(f"[{label}] stolen code      : {r2}")
    print(f"[{label}] implicit grant   : {r3}")

print("\n== 3. Refresh token rotation with reuse detection (secure AS) ==")
a = setup(True)
v, ch = o.pkce_pair()
code = o.client_callback(a.authorize("alice", {"client_id": "spa", "redirect_uri": CB, "response_type": "code",
                                               "state": "x", "code_challenge": ch, "code_challenge_method": "S256"}), "x")
t = a.token({"grant_type": "authorization_code", "code": code, "client_id": "spa", "redirect_uri": CB, "code_verifier": v})
old_rt = t["refresh_token"]
new = a.token({"grant_type": "refresh_token", "refresh_token": old_rt})
print("legit client refreshed, got a NEW refresh token:", new["refresh_token"] != old_rt)
try:
    a.token({"grant_type": "refresh_token", "refresh_token": old_rt})
except ValueError as e:
    print("thief replays the OLD refresh token ->", e)
try:
    a.token({"grant_type": "refresh_token", "refresh_token": new["refresh_token"]})
except ValueError as e:
    print("legit client's new token is now dead too ->", e)

print("\n== 4. Config review ==")
for f in ("client_insecure.json", "client_secure.json"):
    cfg = json.loads((HERE / "fixtures" / f).read_text(encoding="utf-8"))
    findings = o.audit_client_config(cfg)
    print(f"{f}: {len(findings)} finding(s)")
    for x in findings:
        print("  -", x)
