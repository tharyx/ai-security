"""Step definitions for the security feature files. They talk to the SimApp, never to a network."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sim_app as appmod  # noqa: E402
import gherkin_lite as bdd  # noqa: E402

steps = bdd.StepRegistry()
Q = r'"([^"]*)"'


def make_context(vulnerable: bool = False):
    return lambda: bdd.Context(vulnerable=vulnerable, app=None, response=None, cookies={}, remembered=None,
                               session_ids=[])


@steps.step(r"the application is running")
def _running(ctx):
    ctx.app = appmod.SimApp(vulnerable=ctx.vulnerable)


@steps.step(rf"I log in as {Q} with password {Q}")
def _login(ctx, user, pw):
    ctx.response = ctx.app.handle("POST", "/login", {"username": user, "password": pw}, ctx.cookies)
    c = ctx.response.cookie("session")
    if c:
        ctx.cookies["session"] = c["value"]
        ctx.session_ids.append(c["value"])


@steps.step(rf"I fail to log in as {Q} (\d+) times in a row")
def _fail_n(ctx, user, n):
    for _ in range(int(n)):
        ctx.response = ctx.app.handle("POST", "/login", {"username": user, "password": "wrong-password"})


@steps.step(rf"I log in as {Q} with password {Q} in two separate sessions")
def _two_sessions(ctx, user, pw):
    ctx.session_ids = []
    for _ in range(2):
        r = ctx.app.handle("POST", "/login", {"username": user, "password": pw})
        ctx.session_ids.append(r.cookie("session")["value"])


@steps.step(r"I log out")
def _logout(ctx):
    ctx.old_session = ctx.cookies.get("session")
    ctx.response = ctx.app.handle("POST", "/logout", cookies=ctx.cookies)
    ctx.cookies = {}


@steps.step(rf"I request {Q} anonymously")
def _get_anon(ctx, path):
    ctx.response = ctx.app.handle("GET", path)


@steps.step(rf"I request {Q} with my session")
def _get_session(ctx, path):
    ctx.response = ctx.app.handle("GET", path, cookies=ctx.cookies)


@steps.step(rf"I request {Q} with the old session")
def _get_old(ctx, path):
    ctx.response = ctx.app.handle("GET", path, cookies={"session": ctx.old_session})


@steps.step(r"I remember the response body")
def _remember(ctx):
    ctx.remembered = ctx.response.body


# ---- assertions


@steps.step(r"the response status is (\d+)")
def _status(ctx, code):
    assert ctx.response.status == int(code), f"expected status {code}, got {ctx.response.status}"


@steps.step(r"the response status is (\d+) or (\d+)")
def _status_either(ctx, a, b):
    assert ctx.response.status in (int(a), int(b)), f"expected {a} or {b}, got {ctx.response.status}"


@steps.step(rf"the response sets a cookie named {Q}")
def _sets_cookie(ctx, name):
    assert ctx.response.cookie(name), f"no Set-Cookie for '{name}'"


@steps.step(rf"the cookie {Q} has the {Q} flag")
def _cookie_flag(ctx, name, flag):
    c = ctx.response.cookie(name)
    assert c, f"no Set-Cookie for '{name}'"
    assert flag.lower() in c["flags"], f"cookie '{name}' is missing the {flag} flag (has: {sorted(c['flags'])})"


@steps.step(rf"the cookie {Q} has SameSite {Q} or {Q}")
def _cookie_samesite(ctx, name, a, b):
    c = ctx.response.cookie(name)
    assert c, f"no Set-Cookie for '{name}'"
    assert c["attrs"].get("samesite") in (a, b), f"SameSite is {c['attrs'].get('samesite')!r}, want {a} or {b}"


@steps.step(r"the two session ids are different and at least (\d+) characters long")
def _unpredictable(ctx, n):
    a, b = ctx.session_ids[-2:]
    assert a != b, "two logins produced the same session id"
    assert min(len(a), len(b)) >= int(n), f"session id too short ({min(len(a), len(b))} chars)"
    assert not (a[:-4] == b[:-4]), f"session ids look sequential: {a} / {b}"


@steps.step(rf"the response header {Q} is present")
def _hdr_present(ctx, name):
    assert ctx.response.header(name) is not None, f"header {name} is missing"


@steps.step(rf"the response header {Q} contains {Q}")
def _hdr_contains(ctx, name, text):
    v = ctx.response.header(name)
    assert v is not None, f"header {name} is missing"
    assert text.lower() in v.lower(), f"header {name} is {v!r}, expected it to contain {text!r}"


@steps.step(rf"the response header {Q} is absent")
def _hdr_absent(ctx, name):
    assert ctx.response.header(name) is None, f"header {name} should not be sent (got {ctx.response.header(name)!r})"


@steps.step(rf"the response header {Q} does not reveal a version number")
def _hdr_no_version(ctx, name):
    import re
    v = ctx.response.header(name) or ""
    assert not re.search(r"\d+\.\d+", v), f"header {name} reveals a version: {v!r}"


@steps.step(r"the response body is the same as the remembered body")
def _same_body(ctx):
    assert ctx.response.body == ctx.remembered, \
        f"messages differ: {ctx.remembered!r} vs {ctx.response.body!r} (user enumeration)"


@steps.step(rf"the response body does not contain {Q}")
def _body_not(ctx, text):
    assert text not in ctx.response.body, f"body contains {text!r}"
