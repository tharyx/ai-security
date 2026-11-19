"""Security headers analyzer: HSTS, Cache-Control, X-XSS-Protection, X-Frame-Options vs
frame-ancestors, a CSP evaluator, CORS and cookies. Plus vulnerable vs secure CORS origin checks
and a SameSite model for cookie-based vs token-based implementations.

Pure standard library. Header names are matched case-insensitively. Behaviour notes follow current
browser practice (Nov 2026; verify on MDN and the OWASP HTTP Headers Cheat Sheet).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

ONE_YEAR = 31_536_000
RISKY_CDN_HOSTS = ("*.googleapis.com", "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
                   "unpkg.com", "*.cloudfront.net", "*.google.com")


@dataclass
class Finding:
    id: str
    severity: str
    message: str


def _norm(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


# ------------------------------------------------------------------ CSP
def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks and toks[0].lower() not in out:  # first occurrence wins, like browsers
            out[toks[0].lower()] = toks[1:]
    return out


def evaluate_csp(value: str) -> list[Finding]:
    csp = parse_csp(value)
    f: list[Finding] = []
    script = csp.get("script-src", csp.get("default-src"))
    if script is None:
        f.append(Finding("CSP-01", "HIGH", "no script-src or default-src: scripts are unrestricted"))
        script = []
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script)
    if "'unsafe-inline'" in script and not has_nonce_or_hash:
        f.append(Finding("CSP-02", "HIGH", "'unsafe-inline' in script-src without a nonce/hash: inline XSS runs"))
    if "'unsafe-eval'" in script:
        f.append(Finding("CSP-03", "MEDIUM", "'unsafe-eval' allows eval()/new Function()"))
    if any(s in ("*", "http:", "https:", "data:") for s in script) and "'strict-dynamic'" not in script:
        f.append(Finding("CSP-04", "HIGH", "wildcard or scheme source in script-src allows scripts from anywhere"))
    risky = [s for s in script if re.sub(r"^https?://", "", s).rstrip("/") in RISKY_CDN_HOSTS]
    if risky and "'strict-dynamic'" not in script:
        f.append(Finding("CSP-05", "MEDIUM", f"allowlisted CDN hosts can serve JSONP/AngularJS gadgets: {', '.join(risky)}"))
    if csp.get("object-src", csp.get("default-src")) != ["'none'"]:
        f.append(Finding("CSP-06", "MEDIUM", "object-src is not 'none' (plugins can run script)"))
    if "base-uri" not in csp:
        f.append(Finding("CSP-07", "MEDIUM", "no base-uri: an injected <base> tag can hijack relative script URLs"))
    if "frame-ancestors" not in csp:
        f.append(Finding("CSP-08", "LOW", "no frame-ancestors: clickjacking protection relies on X-Frame-Options"))
    if "report-to" not in csp and "report-uri" not in csp:
        f.append(Finding("CSP-09", "LOW", "no reporting endpoint: violations are invisible"))
    return f


def build_strict_csp(nonce: str, report_group: str = "csp") -> str:
    """The pattern recommended by the OWASP CSP cheat sheet and web.dev 'strict CSP' (verify)."""
    return (f"script-src 'nonce-{nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; "
            f"frame-ancestors 'none'; report-to {report_group}")


# ------------------------------------------------------------------ cookies
def parse_set_cookie(value: str) -> tuple[str, dict[str, str | bool]]:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs: dict[str, str | bool] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.lower()] = v
        elif p:
            attrs[p.lower()] = True
    return name, attrs


def check_cookie(value: str, session: bool = True) -> list[Finding]:
    name, a = parse_set_cookie(value)
    f = []
    if session and not a.get("httponly"):
        f.append(Finding("COOKIE-01", "HIGH", f"{name}: no HttpOnly, so any XSS can read the session"))
    if not a.get("secure"):
        f.append(Finding("COOKIE-02", "HIGH", f"{name}: no Secure, so it can travel over plain HTTP"))
    ss = str(a.get("samesite", "")).lower()
    if ss == "":
        f.append(Finding("COOKIE-03", "MEDIUM", f"{name}: no SameSite (Chromium defaults to Lax; others differ) - set it explicitly"))
    elif ss == "none" and not a.get("secure"):
        f.append(Finding("COOKIE-04", "HIGH", f"{name}: SameSite=None without Secure is rejected by browsers"))
    if name.startswith("__Host-") and (not a.get("secure") or a.get("path") != "/" or "domain" in a):
        f.append(Finding("COOKIE-05", "HIGH", f"{name}: __Host- prefix requires Secure, Path=/ and no Domain"))
    if session and not name.startswith("__Host-"):
        f.append(Finding("COOKIE-06", "LOW", f"{name}: consider the __Host- prefix to lock the cookie to this host"))
    return f


def cookie_sent(samesite: str, secure: bool, request: str) -> bool:
    """Simplified SameSite model. request: 'same-site', 'cross-site-top-level-get',
    'cross-site-post', 'cross-site-subresource' (img/fetch/iframe)."""
    s = samesite.lower()
    if s == "none":
        return secure  # browsers drop SameSite=None cookies without Secure
    if request == "same-site":
        return True
    if s == "lax":
        return request == "cross-site-top-level-get"
    return False  # strict


# ------------------------------------------------------------------ CORS
def cors_vulnerable_regex(origin: str) -> bool:
    """VULNERABLE: unanchored suffix check, so https://evil-shop.example.attacker.test passes."""
    return bool(re.search(r"shop\.example", origin))


def cors_vulnerable_reflect(origin: str) -> bool:
    """VULNERABLE: reflect any origin (often with credentials)."""
    return True


def cors_secure(origin: str, allowlist: frozenset[str] = frozenset({"https://shop.example", "https://admin.shop.example"})) -> bool:
    """SECURE: exact match against a list of full origins; 'null' never allowed."""
    return origin in allowlist


def cors_response(origin: str, allow: bool, credentials: bool = True) -> dict[str, str]:
    if not allow:
        return {"Vary": "Origin"}
    h = {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    if credentials:
        h["Access-Control-Allow-Credentials"] = "true"
    return h


# ------------------------------------------------------------------ whole-response analyzer
def analyze(headers: dict[str, str], *, sensitive: bool = True, request_origin: str | None = None,
            https: bool = True, trusted_origins: frozenset[str] = frozenset({"https://shop.example"})) -> list[Finding]:
    h = _norm(headers)
    f: list[Finding] = []

    xxp = h.get("x-xss-protection")
    if xxp is not None and xxp.strip() != "0":
        f.append(Finding("XXP-01", "LOW", f"X-XSS-Protection: {xxp} is deprecated (auditor removed; it caused bugs). Send 0 or omit it and use CSP"))

    if https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            f.append(Finding("HSTS-01", "HIGH", "no Strict-Transport-Security: first request can be downgraded (SSL stripping)"))
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < ONE_YEAR:
                f.append(Finding("HSTS-02", "MEDIUM", "HSTS max-age below one year"))
            if "includesubdomains" not in hsts.lower():
                f.append(Finding("HSTS-03", "LOW", "HSTS without includeSubDomains"))

    if sensitive:
        cc = h.get("cache-control", "").lower()
        if "no-store" not in cc:
            f.append(Finding("CACHE-01", "MEDIUM", "sensitive response without Cache-Control: no-store (shared caches and browser history keep it)"))

    csp = h.get("content-security-policy")
    xfo = h.get("x-frame-options")
    has_fa = bool(csp and "frame-ancestors" in parse_csp(csp))
    if not has_fa and not xfo:
        f.append(Finding("FRAME-01", "MEDIUM", "no frame-ancestors and no X-Frame-Options: clickjacking"))
    elif xfo and not has_fa:
        f.append(Finding("FRAME-02", "LOW", "X-Frame-Options only: prefer CSP frame-ancestors (keep XFO for old browsers)"))
    if xfo and xfo.upper().startswith("ALLOW-FROM"):
        f.append(Finding("FRAME-03", "MEDIUM", "X-Frame-Options ALLOW-FROM is obsolete and ignored by modern browsers; use frame-ancestors"))

    if csp:
        f.extend(evaluate_csp(csp))
    elif "content-security-policy-report-only" in h:
        f.append(Finding("CSP-10", "MEDIUM", "CSP only in Report-Only mode: nothing is blocked yet"))
        f.extend(evaluate_csp(h["content-security-policy-report-only"]))
    else:
        f.append(Finding("CSP-00", "MEDIUM", "no Content-Security-Policy"))

    if h.get("x-content-type-options", "").lower() != "nosniff":
        f.append(Finding("NOSNIFF-01", "LOW", "no X-Content-Type-Options: nosniff"))

    acao, acac = h.get("access-control-allow-origin"), h.get("access-control-allow-credentials", "").lower() == "true"
    if acao:
        if acao == "null":
            f.append(Finding("CORS-01", "HIGH", "Access-Control-Allow-Origin: null (sandboxed iframes and file: pages get access)"))
        if acao == "*" and acac:
            f.append(Finding("CORS-02", "MEDIUM", "'*' with credentials: browsers refuse it, but the config shows intent to reflect"))
        if request_origin and acao == request_origin and acac and request_origin not in trusted_origins:
            f.append(Finding("CORS-03", "CRITICAL", f"origin {request_origin} reflected with credentials: any site can read this response as the user"))

    for k, v in headers.items():
        if k.lower() == "set-cookie":
            f.extend(check_cookie(v))
    if ("server" in h and re.search(r"\d", h["server"])) or "x-powered-by" in h:
        f.append(Finding("INFO-01", "LOW", "Server/X-Powered-By reveal product versions"))
    return f


def ids(findings: list[Finding]) -> set[str]:
    return {x.id for x in findings}
