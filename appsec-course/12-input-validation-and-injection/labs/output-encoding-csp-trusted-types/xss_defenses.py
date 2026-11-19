"""Output encoding per context, a CSP builder/evaluator, and Trusted Types on a fake DOM.

No browser is used. "Breaking out" is judged with simple, explainable checks that
match what a browser parser would do in each context.
"""

from __future__ import annotations

import html
import re
import secrets
from urllib.parse import quote

# ------------------------------------------------------------------ encoders (OWASP rules)


def html_encode(s: str) -> str:
    return html.escape(s, quote=True)  # & < > " '


def attr_encode(s: str) -> str:
    """Encode every non-alphanumeric char as &#xHH; (safe even in unquoted attributes)."""
    return "".join(ch if ch.isalnum() else f"&#x{ord(ch):x};" for ch in s)


def js_string_encode(s: str) -> str:
    """For data inside a quoted JS string: \\xHH / \\uHHHH for non-alphanumerics."""
    out = []
    for ch in s:
        if ch.isalnum() and ord(ch) < 128:
            out.append(ch)
        elif ord(ch) < 256:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


def css_encode(s: str) -> str:
    """For a CSS value: \\HH followed by a space for non-alphanumerics."""
    return "".join(ch if ch.isalnum() else f"\\{ord(ch):x} " for ch in s)


def url_param_encode(s: str) -> str:
    return quote(s, safe="")


TEMPLATES = {
    "html": "<p>Hello {}</p>",
    "attribute": '<input value="{}">',
    "javascript": "<script>var name = '{}';</script>",
    "css": "<div style=\"color: {}\">x</div>",
}
ENCODERS = {"html": html_encode, "attribute": attr_encode, "javascript": js_string_encode, "css": css_encode}


def render(context: str, value: str, encode: bool) -> str:
    return TEMPLATES[context].format(ENCODERS[context](value) if encode else value)


def breaks_out(context: str, rendered: str) -> bool:
    """Did attacker data escape its context? (simplified browser-parser view)"""
    if context == "html":
        return bool(re.search(r"<(script|img|svg|iframe)\b", rendered[3:-4], re.I))
    if context == "attribute":
        inner = rendered[len('<input value="'):-2]
        return '"' in inner or ">" in inner
    if context == "javascript":
        inner = rendered[len("<script>var name = '"):-len("';</script>")]
        return "'" in inner.replace("\\'", "") or "</script" in inner.lower()
    if context == "css":
        inner = rendered[len('<div style="color: '):-len('">x</div>')]
        return any(t in inner for t in (";", '"', "url(", "expression("))
    raise ValueError(context)


# ------------------------------------------------------------------ CSP


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def build_strict_csp(nonce: str, report_uri: str | None = "/csp-report") -> str:
    parts = [f"script-src 'nonce-{nonce}' 'strict-dynamic'", "object-src 'none'", "base-uri 'none'",
             "frame-ancestors 'none'", "require-trusted-types-for 'script'"]
    if report_uri:
        parts.append(f"report-uri {report_uri}")
    return "; ".join(parts)


def parse_csp(header: str) -> dict[str, list[str]]:
    out = {}
    for part in header.split(";"):
        tokens = part.split()
        if tokens:
            out[tokens[0].lower()] = tokens[1:]
    return out


def evaluate_csp(header: str) -> list[str]:
    """Findings in the spirit of Google's CSP Evaluator (simplified)."""
    d = parse_csp(header)
    f = []
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        f.append("HIGH no script-src or default-src: scripts unrestricted")
        script = []
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script)
    if "'unsafe-inline'" in script and not has_nonce_or_hash:
        f.append("HIGH 'unsafe-inline' allows injected inline scripts")
    if "'unsafe-eval'" in script:
        f.append("MEDIUM 'unsafe-eval' allows eval()")
    if any(s in ("*", "http:", "https:", "data:") for s in script):
        f.append("HIGH wildcard or scheme source in script-src")
    if any(s.endswith((".googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net")) for s in script) and "'strict-dynamic'" not in script:
        f.append("MEDIUM CDN host allowlist may host JSONP or old AngularJS gadgets")
    if "object-src" not in d and "'none'" not in d.get("default-src", []):
        f.append("MEDIUM missing object-src 'none' (plugins)")
    if "base-uri" not in d:
        f.append("MEDIUM missing base-uri (base tag hijacking of relative scripts)")
    return f


def browser_runs_inline_script(csp: str | None, script_tag: str) -> bool:
    """Would a CSP-aware browser execute this inline <script>?"""
    if csp is None:
        return True
    script = parse_csp(csp).get("script-src", parse_csp(csp).get("default-src", ["*"]))
    m = re.search(r"nonce=\"([^\"]+)\"", script_tag)
    if m and f"'nonce-{m.group(1)}'" in script:
        return True
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha")) for s in script)
    return "'unsafe-inline'" in script and not has_nonce_or_hash


# ------------------------------------------------------------------ Trusted Types (simulated)


class TrustedHTML(str):
    pass


class TrustedTypePolicy:
    def __init__(self, name, create_html):
        self.name, self._create_html = name, create_html

    def createHTML(self, s: str) -> TrustedHTML:
        return TrustedHTML(self._create_html(s))


class FakeElement:
    """A DOM element with the dangerous innerHTML sink."""

    def __init__(self, enforce_trusted_types: bool, default_policy: TrustedTypePolicy | None = None):
        self.enforce, self.default_policy, self._html = enforce_trusted_types, default_policy, ""

    @property
    def innerHTML(self):
        return self._html

    @innerHTML.setter
    def innerHTML(self, value):
        if self.enforce and not isinstance(value, TrustedHTML):
            if self.default_policy is None:
                raise TypeError("This document requires 'TrustedHTML' assignment.")
            value = self.default_policy.createHTML(value)
        self._html = str(value)


def simple_sanitizer(s: str) -> str:
    """Tiny allowlist sanitizer for the lab: keep <b>, <i>, <p>; drop other tags and on* handlers.
    In real code use DOMPurify (browser) or a maintained server-side sanitizer."""
    s = re.sub(r"<\s*(script|style)[^>]*>.*?<\s*/\s*\1\s*>", "", s, flags=re.I | re.S)
    s = re.sub(r"<(?!/?(b|i|p)>)[^>]*>", "", s, flags=re.I)
    return s


def element_has_script(el: FakeElement) -> bool:
    return bool(re.search(r"<script|onerror\s*=|onload\s*=", el.innerHTML, re.I))


# ------------------------------------------------------------------ nested contexts


def onclick_handler_breaks_out(value: str, encoder) -> bool:
    """<a onclick="go('VALUE')">: the browser HTML-decodes the attribute FIRST, then runs JS.
    So HTML-encoding a quote (&#x27;) does not protect the JS string; JS-encoding (\x27) does."""
    rendered = f"<a onclick=\"go('{encoder(value)}')\">"
    attr = html.unescape(rendered[len('<a onclick="'):-2])  # what the JS engine receives
    js_string = attr[len("go('"):-len("')")]
    return "'" in js_string
