"""Privilege escalation with stored XSS, using a SIMULATED browser.

The "browser" renders HTML, finds <script> blocks, checks CSP nonces and runs a tiny,
safe script language (not JavaScript) with two commands:
    steal(document.cookie)                    -> sends readable cookies to the attacker's log
    call(METHOD, PATH, BODY)                  -> same-origin request with the victim's cookies
That is enough to show the real attack: mallory posts a comment; when the admin opens the
moderation page, the script runs AS THE ADMIN and promotes mallory.

Defences, each tested separately:
  encode   - HTML-encode comments on output (the fix)
  httponly - session cookie is HttpOnly (stops cookie theft, NOT same-origin actions)
  csp      - strict CSP with a nonce (injected script does not run)
  csrf     - admin actions need POST + an anti-CSRF token not readable by the script
"""

from __future__ import annotations

import html
import re
import secrets
from dataclasses import dataclass, field

ATTACKER_LOG: list[str] = []


@dataclass
class App:
    encode: bool = False
    httponly: bool = False
    csp: bool = False
    csrf: bool = False
    comments: list[str] = field(default_factory=list)
    roles: dict = field(default_factory=lambda: {"admin": "admin", "mallory": "user"})
    sessions: dict = field(default_factory=dict)
    csrf_tokens: dict = field(default_factory=dict)

    def login(self, user):
        sid = "FAKE-sid-" + secrets.token_hex(6)
        self.sessions[sid] = user
        self.csrf_tokens[sid] = secrets.token_hex(8)
        return sid

    def post_comment(self, text):
        self.comments.append(text)

    def moderation_page(self, sid):
        nonce = secrets.token_hex(8)
        body = "".join(f"<li>{html.escape(c) if self.encode else c}</li>" for c in self.comments)
        page = f"<h1>Moderation</h1><ul>{body}</ul><script nonce=\"{nonce}\">ui.init()</script>"
        headers = {"Set-Cookie": f"sid={sid}; Secure; SameSite=Lax" + ("; HttpOnly" if self.httponly else "")}
        if self.csp:
            headers["Content-Security-Policy"] = f"script-src 'nonce-{nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'"
        return page, headers

    def api(self, method, path, body, cookie_sid, csrf_header=None):
        user = self.sessions.get(cookie_sid)
        if user is None or self.roles.get(user) != "admin":
            return 403
        m = re.fullmatch(r"/api/admin/users/(\w+)/role", path)
        if not m:
            return 404
        if self.csrf and (method != "POST" or csrf_header != self.csrf_tokens[cookie_sid]):
            return 403
        self.roles[m.group(1)] = body
        return 200


class SimBrowser:
    def __init__(self, app: App, sid: str):
        self.app, self.sid = app, sid

    def visit_moderation(self):
        page, headers = self.app.moderation_page(self.sid)
        cookie_readable = "HttpOnly" not in headers["Set-Cookie"]
        csp = headers.get("Content-Security-Policy", "")
        allowed_nonce = re.search(r"'nonce-([0-9a-f]+)'", csp)
        ran = []
        for attrs, code in re.findall(r"<script([^>]*)>(.*?)</script>", page, re.S):
            if csp:
                m = re.search(r'nonce="([0-9a-f]+)"', attrs)
                if not (m and allowed_nonce and m.group(1) == allowed_nonce.group(1)):
                    continue  # blocked by CSP
            ran.append(code)
            for cmd in code.split(";"):
                cmd = cmd.strip()
                if cmd == "steal(document.cookie)":
                    ATTACKER_LOG.append(f"sid={self.sid}" if cookie_readable else "")
                elif cmd.startswith("call("):
                    method, path, body = [a.strip().strip("'\"") for a in cmd[5:-1].split(",")]
                    self.app.api(method, path, body, self.sid, csrf_header=None)  # script cannot read the token
        return ran


MALICIOUS_COMMENT = "Great product!<script>steal(document.cookie); call('POST', '/api/admin/users/mallory/role', 'admin')</script>"


def run_attack(**defences) -> dict:
    ATTACKER_LOG.clear()
    app = App(**defences)
    app.post_comment(MALICIOUS_COMMENT)  # mallory, a normal user
    admin_sid = app.login("admin")
    SimBrowser(app, admin_sid).visit_moderation()
    stolen = [x for x in ATTACKER_LOG if x]
    return {"mallory_role": app.roles["mallory"], "cookie_stolen": bool(stolen)}
