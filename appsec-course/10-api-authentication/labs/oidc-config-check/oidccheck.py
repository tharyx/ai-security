"""Audit an OpenID Connect discovery document (/.well-known/openid-configuration)
and the ID-token claims a client receives.

Covers "Insecure OpenID Connect Configuration" and "OIDC Authentication".
Offline: the discovery documents are JSON fixtures; nothing is fetched.

Checks follow RFC 9700 (OAuth 2.0 Security BCP), OpenID Connect Core and the
OAuth 2.1 draft direction (verify at source).

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str


def load(path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def check_discovery(doc: dict, expected_issuer: str) -> list:
    f = []
    if doc.get("issuer") != expected_issuer:
        f.append(Finding("OIDC-ISSUER-MISMATCH", "High",
                         f"issuer {doc.get('issuer')!r} != expected {expected_issuer!r}"))
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        if key in doc and urlsplit(doc[key]).scheme != "https":
            f.append(Finding("OIDC-NO-TLS", "High", f"{key} is not https"))
    issuer_host = urlsplit(doc.get("issuer", "")).hostname
    if "jwks_uri" in doc and urlsplit(doc["jwks_uri"]).hostname != issuer_host:
        f.append(Finding("OIDC-JWKS-OFFSITE", "Medium",
                         "jwks_uri host differs from issuer host; confirm it is intended"))
    algs = doc.get("id_token_signing_alg_values_supported", [])
    if "none" in algs:
        f.append(Finding("OIDC-ALG-NONE", "Critical", "unsigned ID tokens allowed"))
    if any(a.startswith("HS") for a in algs):
        f.append(Finding("OIDC-HS-ALG", "Medium",
                         "HS* ID tokens are signed with the client secret; prefer RS256/ES256"))
    rts = doc.get("response_types_supported", [])
    if any("token" in rt.split() for rt in rts):
        f.append(Finding("OIDC-IMPLICIT", "High",
                         "implicit/hybrid response types return tokens in the URL fragment"))
    grants = doc.get("grant_types_supported", [])
    if "implicit" in grants:
        f.append(Finding("OAUTH-IMPLICIT-GRANT", "High", "implicit grant is removed in OAuth 2.1 / RFC 9700"))
    if "password" in grants:
        f.append(Finding("OAUTH-ROPC-GRANT", "High", "resource owner password grant is removed in OAuth 2.1"))
    pkce = doc.get("code_challenge_methods_supported")
    if not pkce:
        f.append(Finding("OAUTH-NO-PKCE", "High", "PKCE not advertised"))
    elif "S256" not in pkce:
        f.append(Finding("OAUTH-PKCE-PLAIN", "Medium", "only 'plain' PKCE; require S256"))
    if "none" in doc.get("token_endpoint_auth_methods_supported", []):
        f.append(Finding("OAUTH-PUBLIC-CLIENTS", "Info",
                         "public clients allowed; acceptable only with PKCE S256"))
    return f


def validate_id_token_claims(claims: dict, *, issuer: str, client_id: str,
                             nonce: str, now: int) -> list:
    """Return a list of problems with already signature-verified ID-token claims."""
    problems = []
    if claims.get("iss") != issuer:
        problems.append("iss mismatch")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if client_id not in auds:
        problems.append("aud does not contain our client_id")
    if isinstance(aud, list) and len(auds) > 1 and claims.get("azp") != client_id:
        problems.append("multiple audiences but azp is not our client_id")
    if int(claims.get("exp", 0)) <= now:
        problems.append("expired or missing exp")
    if claims.get("nonce") != nonce:
        problems.append("nonce mismatch (possible replay)")
    return problems


def gate(findings: list) -> int:
    return 1 if any(x.severity in ("Critical", "High") for x in findings) else 0
