"""A tiny Zest-subset interpreter and a ZAP-context login helper. Loopback only.

Real Zest (ZAP by Checkmarx scripting format) is a JSON-serialised list of statements: requests,
assertions, assignments, conditionals, loops and actions, created by recording in a browser or
edited in ZAP. This file implements a small subset with the same flavour:

  ZestRequest             send a request (method, url, headers, data, assertions)
  ZestAssertStatusCode    response status must equal ``code``
  ZestAssertBodyContains  response body must contain ``text``
  ZestAssignFromJson      variable = value at a JSON path of the last response
  ZestAssignRegex         variable = first capture group of a regex on the last response body
  ZestAssignString        variable = a literal

``{{name}}`` in any string is replaced by the variable. Redirects are NOT followed on purpose:
you want to see the Set-Cookie of the login response itself.
"""

from __future__ import annotations

import http.client
import json
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml


class ZestError(Exception):
    pass


@dataclass
class StepResult:
    index: int
    summary: str
    ok: bool = True
    detail: str = ""


@dataclass
class ZestResult:
    variables: dict
    steps: list = field(default_factory=list)
    cookies: dict = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(s.ok for s in self.steps)


def _subst(text, variables):
    if not isinstance(text, str):
        return text
    return re.sub(r"\{\{(\w+)\}\}", lambda m: str(variables.get(m.group(1), m.group(0))), text)


def _loopback(url):
    if urlparse(url).hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ZestError("scope guard: loopback targets only")


def http_call(method, url, headers=None, data=None, cookies=None):
    _loopback(url)
    p = urlparse(url)
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=5)
    h = dict(headers or {})
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    path = p.path + (f"?{p.query}" if p.query else "")
    try:
        conn.request(method, path or "/", body=data.encode() if data else None, headers=h)
        r = conn.getresponse()
        body = r.read().decode(errors="replace")
        set_cookies = {}
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                set_cookies[name] = rest.split(";")[0]
        return r.status, body, set_cookies
    finally:
        conn.close()


def run_script(script: dict, base: str, overrides: dict | None = None) -> ZestResult:
    variables = {**script.get("variables", {}), "base": base, **(overrides or {})}
    result = ZestResult(variables)
    last_body, last_status = "", 0
    for st in script["statements"]:
        kind, idx = st["elementType"], st.get("index", 0)
        if kind == "ZestRequest":
            url = _subst(st["url"], variables)
            headers = {k: _subst(v, variables) for k, v in st.get("headers", {}).items()}
            data = _subst(st.get("data"), variables)
            last_status, last_body, sc = http_call(st["method"], url, headers, data, result.cookies)
            result.cookies.update(sc)
            result.steps.append(StepResult(idx, f"{st['method']} {urlparse(url).path} -> {last_status}"))
            for a in st.get("assertions", []):
                ok, why = _assert(a, last_status, last_body, variables)
                result.steps.append(StepResult(idx, f"  assert {a['elementType']}", ok, "" if ok else why))
        elif kind == "ZestAssignFromJson":
            try:
                value = json.loads(last_body)
                for part in st["path"].split("."):
                    value = value[part]
                variables[st["variable"]] = value
                result.steps.append(StepResult(idx, f"{st['variable']} = <json {st['path']}>"))
            except (ValueError, KeyError, TypeError):
                result.steps.append(StepResult(idx, f"assign {st['variable']}", False, "JSON path not found"))
        elif kind == "ZestAssignRegex":
            m = re.search(st["regex"], last_body)
            if m:
                variables[st["variable"]] = m.group(1)
                result.steps.append(StepResult(idx, f"{st['variable']} = {m.group(1)!r}"))
            else:
                result.steps.append(StepResult(idx, f"assign {st['variable']}", False, "regex did not match"))
        elif kind == "ZestAssignString":
            variables[st["variable"]] = _subst(st["string"], variables)
            result.steps.append(StepResult(idx, f"{st['variable']} = literal"))
        else:
            raise ZestError(f"statement type not supported by this subset: {kind}")
        if not result.passed:
            break  # real Zest stops the script on a failed assertion
    return result


def _assert(a, status, body, variables):
    if a["elementType"] == "ZestAssertStatusCode":
        return status == a["code"], f"expected {a['code']}, got {status}"
    if a["elementType"] == "ZestAssertBodyContains":
        text = _subst(a["text"], variables)
        return text in body, f"body does not contain {text!r}"
    raise ZestError(f"assertion not supported: {a['elementType']}")


# ------------------------------------------------------------------ ZAP context helper
def load_context(path, base: str) -> dict:
    text = open(path).read().replace("{{base}}", base)
    return yaml.safe_load(text)["env"]["contexts"][0]


def login_with_context(ctx: dict, env: dict | None = None) -> dict:
    """Perform the login the context describes. Returns request headers to attach to later requests."""
    env = env if env is not None else dict(os.environ)
    auth = ctx["authentication"]
    params = auth["parameters"]
    user = ctx["users"][0]["credentials"]
    pwd = re.sub(r"\$\{(\w+)\}", lambda m: env[m.group(1)], user["password"])  # secret comes from the environment
    body = params["loginRequestBody"].replace("{%username%}", user["username"]).replace("{%password%}", pwd)
    method = auth["method"]
    if method == "form":
        status, _, cookies = http_call("POST", params["loginRequestUrl"], {"Content-Type": "application/x-www-form-urlencoded"}, body)
        if not cookies:
            raise ZestError(f"form login failed (status {status})")
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}
    if method == "json":
        status, text, _ = http_call("POST", params["loginRequestUrl"], {"Content-Type": "application/json"}, body)
        if status != 200:
            raise ZestError(f"json login failed (status {status})")
        return {params.get("headerName", "Authorization"): params.get("headerValuePrefix", "") + json.loads(text)[params["tokenField"]]}
    raise ZestError(f"authentication method not supported in this lab: {method}")


def is_logged_in(ctx: dict, headers: dict) -> bool:
    v = ctx["authentication"]["verification"]
    status, body, _ = http_call("GET", v["verifyUrl"], headers)
    if v.get("loggedOutRegex") and re.search(re.sub(r"\\[QE]", "", v["loggedOutRegex"]), body):
        return False
    return bool(re.search(re.sub(r"\\[QE]", "", v["loggedInRegex"]), body))
