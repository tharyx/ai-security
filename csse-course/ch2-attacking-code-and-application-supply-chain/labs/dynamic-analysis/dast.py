"""A small DAST: crawl a local target, then probe each parameter for reflected XSS, SQL injection and SSRF.

SAFETY: refuses any target that is not 127.0.0.1 / localhost. Probes are harmless markers.
Real DAST tools (OWASP ZAP, Burp, Nuclei) do much more, and must only be pointed at systems you own
or have written permission to test.
"""

from __future__ import annotations

import html
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

XSS_MARKER = "<csse7f3a>"
SSRF_CANARY = "FAKE-INTERNAL-CRED"
URL_PARAM_HINTS = ("url", "uri", "link", "target", "dest", "redirect", "src")
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@dataclass
class Finding:
    kind: str
    path: str
    param: str
    evidence: str


@dataclass
class Resp:
    status: int
    headers: dict[str, str]
    body: str


def check_local(base: str) -> None:
    host = urllib.parse.urlparse(base).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"refusing to scan non-local target {host!r}")


def get(url: str) -> Resp:
    try:
        with _OPENER.open(url, timeout=5) as r:
            return Resp(r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return Resp(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode("utf-8", "replace"))


def crawl(base: str, max_pages: int = 20) -> dict[str, set[str]]:
    """Return {path: {param names}} discovered from links and GET forms on the same origin."""
    check_local(base)
    seen: set[str] = set()
    todo = ["/"]
    found: dict[str, set[str]] = {}
    while todo and len(seen) < max_pages:
        path = todo.pop()
        if path in seen:
            continue
        seen.add(path)
        page = get(base + path)
        for href in re.findall(r'href="([^"]+)"', page.body):
            u = urllib.parse.urlparse(href)
            if u.netloc:
                continue
            found.setdefault(u.path, set()).update(urllib.parse.parse_qs(u.query))
            if u.path not in seen:
                todo.append(u.path)
        for m in re.finditer(r'<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>', page.body, re.S):
            names = re.findall(r'name="([^"]+)"', m.group(2))
            found.setdefault(m.group(1), set()).update(names)
    return found


def strip_echo(body: str, payload: str) -> str:
    return body.replace(payload, "").replace(html.escape(payload), "")


def probe(base: str, path: str, param: str) -> list[Finding]:
    out: list[Finding] = []

    def call(value: str) -> Resp:
        return get(f"{base}{path}?{urllib.parse.urlencode({param: value})}")

    r = call(XSS_MARKER)
    if XSS_MARKER in r.body:
        out.append(Finding("reflected-xss", path, param, "marker came back unescaped"))
    r = call("1'")
    if r.status == 500 or "database error" in r.body.lower() or "sqlite" in r.body.lower():
        out.append(Finding("sqli-error", path, param, "database error text after a quote"))
    t_payload, f_payload = "1 AND 1=1", "1 AND 1=2"
    t, f = call(t_payload), call(f_payload)
    # A page that just echoes the input would differ for any two payloads (a classic DAST false
    # positive), so remove the echoed payload (raw or HTML-escaped) before comparing.
    if t.status == 200 and f.status == 200 and strip_echo(t.body, t_payload) != strip_echo(f.body, f_payload):
        out.append(Finding("sqli-boolean", path, param, "true and false conditions give different pages"))
    if any(h in param.lower() for h in URL_PARAM_HINTS):
        r = call(f"{base}/internal/metadata")
        if SSRF_CANARY in r.body:
            out.append(Finding("ssrf", path, param, "server fetched an internal URL and returned its content"))
    return out


def passive_checks(base: str) -> list[Finding]:
    r = get(base + "/")
    out = []
    if "content-security-policy" not in r.headers:
        out.append(Finding("missing-header", "/", "-", "Content-Security-Policy"))
    if "x-content-type-options" not in r.headers:
        out.append(Finding("missing-header", "/", "-", "X-Content-Type-Options"))
    return out


def scan(base: str) -> list[Finding]:
    check_local(base)
    findings = passive_checks(base)
    for path, params in sorted(crawl(base).items()):
        for p in sorted(params):
            findings.extend(probe(base, path, p))
    return findings
