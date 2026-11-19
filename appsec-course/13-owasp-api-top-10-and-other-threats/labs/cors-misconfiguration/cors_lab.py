"""Abusing CORS misconfigurations, with a simulated browser that enforces the CORS
read rules. CORS relaxes the same-origin policy; it never adds protection.

Vulnerable policies seen in real APIs:
  reflect  - echo any Origin back, with Access-Control-Allow-Credentials: true
  null     - allow the "null" origin (sandboxed iframes and file:// pages can send it)
  suffix   - origin.endswith("bank.example")  -> "https://evilbank.example" passes
  prefix   - origin.startswith("https://bank.example") -> "https://bank.example.evil.net" passes
  wildcard - "*" (browsers refuse to combine it with credentials)
Secure: exact allowlist, Vary: Origin, credentials only for listed origins.
"""

from __future__ import annotations

ALLOWED = {"https://bank.example", "https://app.bank.example"}
ACCOUNT = {"user": "alice", "balance": 250000, "api_key": "FAKE-key-0000"}


def cors_headers(origin: str | None, policy: str) -> dict:
    if origin is None:
        return {}
    ok = {
        "reflect": True,
        "null": origin == "null" or origin in ALLOWED,
        "suffix": origin.endswith("bank.example"),
        "prefix": origin.startswith("https://bank.example"),
        "wildcard": True,
        "secure": origin in ALLOWED,
    }[policy]
    if not ok:
        return {"Vary": "Origin"}
    if policy == "wildcard":
        return {"Access-Control-Allow-Origin": "*"}
    return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Vary": "Origin"}


def api_account(request_headers: dict, policy: str):
    authed = request_headers.get("Cookie") == "sid=FAKE-alice"
    body = ACCOUNT if authed else {"error": "login"}
    return body, cors_headers(request_headers.get("Origin"), policy)


def browser_cross_origin_read(page_origin: str, policy: str, with_credentials: bool = True):
    """Can JavaScript on page_origin read the response of a fetch to the API?
    The browser attaches the victim's cookie when credentials are included."""
    req = {"Origin": page_origin}
    if with_credentials:
        req["Cookie"] = "sid=FAKE-alice"
    body, h = api_account(req, policy)
    acao, acac = h.get("Access-Control-Allow-Origin"), h.get("Access-Control-Allow-Credentials")
    if acao == "*" and with_credentials:
        return None
    if acao not in ("*", page_origin):
        return None
    if with_credentials and acac != "true":
        return None
    return body


def simple_post_reaches_server(content_type: str) -> bool:
    """CORS is not CSRF protection: 'simple' requests are sent without a preflight.
    CORS only decides whether the attacker's script can READ the response."""
    return content_type in ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
