"""Step definitions for the security scenarios.

register(step) receives the @step decorator from bddlite, so this file needs no import of it.
Each step talks to ctx["app"] (the simulated app) and keeps the last response in ctx["resp"].
"""


def register(step):
    @step(r"a fresh application")
    def fresh(ctx):
        assert ctx["app"] is not None

    @step(r'I submit a wrong password (\d+) times for "(\w+)"')
    def wrong_pw(ctx, n, user):
        for _ in range(int(n)):
            ctx["resp"] = ctx["app"].handle("POST", "/login", form={"user": user, "password": "wrong"})

    @step(r'I log in as "(\w+)" with password "([^"]*)"')
    def login(ctx, user, pw):
        ctx["resp"] = ctx["app"].handle("POST", "/login", form={"user": user, "password": pw})

    @step(r'I search for "(.*)"')
    def search(ctx, q):
        ctx["resp"] = ctx["app"].handle("GET", "/search", params={"q": q})

    @step(r'I request "(/[^"]*)"')
    def request(ctx, path):
        ctx["resp"] = ctx["app"].handle("GET", path)

    @step(r"the response status is (\d+)")
    def status_is(ctx, code):
        got = ctx["resp"].status
        assert got == int(code), f"expected status {code}, got {got}"

    @step(r"the response status is not (\d+)")
    def status_is_not(ctx, code):
        got = ctx["resp"].status
        assert got != int(code), f"status was {got}, which must not happen"

    @step(r'the response body does not contain "([^"]*)"')
    def body_lacks(ctx, text):
        assert text not in ctx["resp"].body, f"body leaked {text!r}: {ctx['resp'].body!r}"

    @step(r'the response header "([\w-]+)" is "([^"]*)"')
    def header_is(ctx, name, value):
        got = ctx["resp"].headers.get(name)
        assert got == value, f"header {name} is {got!r}, expected {value!r}"

    @step(r'the response header "([\w-]+)" is present')
    def header_present(ctx, name):
        assert name in ctx["resp"].headers, f"header {name} is missing"

    @step(r'the response header "([\w-]+)" is absent')
    def header_absent(ctx, name):
        assert name not in ctx["resp"].headers, f"header {name} must not be sent"

    @step(r'the cookie "(\w+)" has the flags "([^"]*)"')
    def cookie_flags(ctx, name, flags):
        raw = next((c for c in ctx["resp"].cookies if c.startswith(name + "=")), None)
        assert raw is not None, f"no cookie named {name}"
        missing = [f for f in (x.strip() for x in flags.split(",")) if f.lower() not in raw.lower()]
        assert not missing, f"cookie {name} lacks {missing}"
