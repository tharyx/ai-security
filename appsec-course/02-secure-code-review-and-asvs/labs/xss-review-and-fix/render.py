"""A profile page rendered two ways: vulnerable string-building, and context-aware output encoding.

Five output contexts, five different rules:
  HTML body        -> html.escape(value)
  HTML attribute   -> always quote the attribute AND html.escape(value, quote=True)
  URL in href/src  -> allow only http/https (block javascript:, data:), then attribute-encode
  JS string        -> json.dumps(value) and escape <, >, & as \\u003c ... so </script> cannot close the block
  CSS value        -> do not encode, VALIDATE against a strict allowlist (e.g. #rrggbb)

``xss_findings`` is a tiny oracle built on html.parser: it reports markup that would execute.
In real projects a template engine with auto-escaping does most of this; reviewers look for the
places where it is switched off (|safe, Markup, innerHTML, dangerouslySetInnerHTML).
"""

from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

TEMPLATE_SCRIPTS = 1  # the page itself has exactly one inline script


def page_vuln(u: dict) -> str:
    return (
        f"<h2>{u['name']}</h2>"
        f"<a href=\"{u['website']}\">website</a>"
        f"<div title={u['bio']}>bio</div>"
        f"<script>var nick = \"{u['nickname']}\";</script>"
        f"<p style=\"color: {u['color']}\">colour</p>"
    )


def enc_html(s: str) -> str:
    return html.escape(s, quote=True)


def enc_url(s: str) -> str:
    s = s.strip()
    scheme = urlsplit(s).scheme.lower()
    if scheme not in ("http", "https"):
        return "#"
    return html.escape(s, quote=True)


def enc_js_string(s: str) -> str:
    return json.dumps(s).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


COLOR = re.compile(r"#[0-9a-fA-F]{6}")


def enc_css_color(s: str) -> str:
    return s if COLOR.fullmatch(s) else "#000000"


def page_secure(u: dict) -> str:
    return (
        f"<h2>{enc_html(u['name'])}</h2>"
        f"<a href=\"{enc_url(u['website'])}\">website</a>"
        f"<div title=\"{enc_html(u['bio'])}\">bio</div>"
        f"<script>var nick = {enc_js_string(u['nickname'])};</script>"
        f"<p style=\"color: {enc_css_color(u['color'])}\">colour</p>"
    )


# ---------------------------------------------------------------- the oracle

JS_STRING_ONLY = re.compile(r'\s*var nick = "(?:[^"\\\n]|\\.)*";\s*')
DANGEROUS_URL = re.compile(r"^\s*(javascript|vbscript|data):", re.I)


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.findings: list = []
        self.scripts = 0
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.scripts += 1
            self._in_script = True
        if tag in ("img", "svg", "iframe", "object", "embed"):
            self.findings.append(f"injected <{tag}> element")
        for name, value in attrs:
            value = value or ""
            if name.startswith("on"):
                self.findings.append(f"event handler attribute {name}= on <{tag}>")
            if name in ("href", "src", "action", "formaction") and DANGEROUS_URL.match(
                    re.sub(r"[\x00-\x20]", "", value)):
                self.findings.append(f"dangerous URL scheme in {name}")
            if name == "style" and re.search(r"expression\(|javascript:|url\(", value, re.I):
                self.findings.append("script-capable CSS in style")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and self.scripts == 1 and not JS_STRING_ONLY.fullmatch(data):
            self.findings.append("JS string context broken out of")


def xss_findings(page: str) -> list:
    c = _Collector()
    c.feed(page)
    c.close()
    if c.scripts > TEMPLATE_SCRIPTS:
        c.findings.append(f"{c.scripts - TEMPLATE_SCRIPTS} extra <script> element(s)")
    return c.findings


SAFE_USER = {"name": "Asha Rao", "website": "https://asha.example/blog?a=1&b=2",
             "bio": "DBA turned AppSec", "nickname": "asha", "color": "#336699"}

PAYLOADS = {
    "name": "<script>alert(1)</script>",
    "website": "javascript:alert(1)",
    "bio": "x onmouseover=alert(1)",
    "nickname": "\";alert(1);//",
    "color": "red;background:url(javascript:alert(1))",
}


def with_payload(field: str) -> dict:
    u = dict(SAFE_USER)
    u[field] = PAYLOADS[field]
    return u
