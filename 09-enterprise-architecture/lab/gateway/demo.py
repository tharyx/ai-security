"""Scorecard: the same attacks against a thin proxy and a secure AI gateway.

From the repository root:
    python 09-enterprise-architecture/lab/gateway/demo.py

Columns:
  vulnerable   the hackathon proxy (vulnerable_gateway.py)
  secure       every layer on, including the soft guardrail
  secure-hard  soft guardrail OFF: only deterministic controls are left
"""

from __future__ import annotations

import attacks
from ai_gateway import SecureGateway, TokenIssuer, make_endpoints
from vulnerable_gateway import SHARED_API_KEY, VulnerableGateway

ISSUER = TokenIssuer(b"lab-only-signing-key")


def secure_cred(user: str, **claims) -> str:
    u = attacks.USERS[user]
    return ISSUER.issue(u["sub"], u["tenant"], u["kind"], on_behalf_of=u.get("on_behalf_of"), **claims)


def vulnerable_cred(user: str, **claims) -> str:
    return SHARED_API_KEY  # every caller holds the same key


COLUMNS = {
    "vulnerable": (lambda eps: VulnerableGateway(eps), vulnerable_cred),
    "secure": (lambda eps: SecureGateway(ISSUER, eps), secure_cred),
    "secure-hard": (lambda eps: SecureGateway(ISSUER, eps, guardrail=None), secure_cred),
}


def main() -> None:
    print(f"{'case':28}{'vulnerable':29}{'secure':24}{'secure-hard':24}stopped by (secure-hard)")
    print("-" * 140)
    for name, fn in {**attacks.SCENARIOS, **attacks.BENIGN}.items():
        out = {col: fn(make, cred, make_endpoints) for col, (make, cred) in COLUMNS.items()}
        why = out["secure-hard"].reason or "-"
        if name.startswith("benign"):
            why = "- (benign: should succeed)"
        print(f"{name:28}{out['vulnerable'].label:29}{out['secure'].label:24}{out['secure-hard'].label:24}{why}")
    print()
    print("CAPITALS = real impact (data reached an unapproved model, crossed tenants, or a")
    print("credential was logged). lowercase = no impact. The secure-hard column has no")
    print("guardrail: prompt_attack is answered, but the gateway holds no data or tools for it to")
    print("abuse. Tip: SecureGateway(..., cache_isolation=False) or routing_policy=False, re-run.")


if __name__ == "__main__":
    main()
