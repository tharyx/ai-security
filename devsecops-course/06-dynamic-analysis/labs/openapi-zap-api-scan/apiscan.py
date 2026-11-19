"""Read an OpenAPI 3 spec, generate test requests for every operation, run them, report.

This is the idea behind ``zap-api-scan.py -f openapi`` and the Automation Framework ``openapi`` job:
the spec tells the scanner every endpoint and parameter that a spider could never discover.
Loopback only.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse

import yaml

METHODS = ("get", "post", "put", "patch", "delete")
SQL_ERR = re.compile(r"sqlite error|syntax error|unrecognized token|unterminated", re.I)
INJECTION_PROBES = ("'", "' OR '1'='1")


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    params: tuple      # ((name, location, type), ...)
    secured: bool
    has_body: bool


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    endpoint: str
    evidence: str


def load_spec(path) -> dict:
    spec = yaml.safe_load(Path(path).read_text())
    if not str(spec.get("openapi", "")).startswith("3."):
        raise ValueError("only OpenAPI 3.x is supported in this lab")
    return spec


def endpoints(spec: dict) -> list:
    global_sec = bool(spec.get("security"))
    out = []
    for path, item in spec.get("paths", {}).items():
        for method in METHODS:
            op = item.get(method)
            if not op:
                continue
            params = tuple(
                (p["name"], p["in"], (p.get("schema") or {}).get("type", "string"))
                for p in op.get("parameters", []) + item.get("parameters", [])
            )
            out.append(Endpoint(method.upper(), path, params, bool(op.get("security", global_sec)), "requestBody" in op))
    return out


def _call(method, url, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def fill_path(path: str, values: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: quote(str(values.get(m.group(1), 1))), path)


def generate_requests(ep: Endpoint) -> list:
    """Return (label, kind, path, query) tuples. ``kind`` tells the runner how to judge the answer."""
    reqs = [("baseline", "baseline", fill_path(ep.path, {}), {})]
    if ep.secured:
        reqs.append(("no-auth", "no-auth", fill_path(ep.path, {}), {}))
    for name, loc, typ in ep.params:
        if typ == "integer":
            if loc == "path":
                reqs.append((f"bola:{name}", "bola", ep.path, {name: "other-user-id"}))
            continue
        for probe in INJECTION_PROBES:
            if loc == "query":
                reqs.append((f"inject:{name}={probe}", "inject", fill_path(ep.path, {}), {name: probe}))
    return reqs


def scan(spec: dict, base: str, creds: dict, other_user_object_ids: dict) -> tuple:
    """creds: {"user": ..., "password": ...}. other_user_object_ids: {"orderId": 2} -> id owned by someone else."""
    host = urlparse(base).hostname
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("scope guard: loopback targets only")
    status, body = _call("POST", base + "/api/v1/login", body={"username": creds["user"], "password": creds["password"]})
    token = json.loads(body)["token"] if status == 200 else ""
    auth = {"Authorization": f"Bearer {token}"}
    findings: list = []
    sent = 0
    for ep in endpoints(spec):
        if ep.method == "POST":
            continue  # the login call above is the only POST in this lab; real tools fuzz bodies too
        label = f"{ep.method} {ep.path}"
        for name, kind, path, query in generate_requests(ep):
            if kind == "bola":
                pname = name.split(":")[1]
                url = base + fill_path(ep.path, {pname: other_user_object_ids[pname]})
                st, bd = _call(ep.method, url, auth)
                sent += 1
                if st == 200:
                    findings.append(Finding("API-BOLA", "High", label, f"{creds['user']} read object {other_user_object_ids[pname]} owned by someone else"))
                continue
            qs = "&".join(f"{k}={quote(v)}" for k, v in query.items())
            url = base + path + ("?" + qs if qs else "")
            st, bd = _call(ep.method, url, None if kind == "no-auth" else auth)
            sent += 1
            if kind == "baseline" and st >= 500:
                findings.append(Finding("API-SERVER-ERROR", "Medium", label, f"baseline request returned {st}"))
            elif kind == "no-auth" and st == 200:
                findings.append(Finding("API-AUTH-MISSING", "High", label, "spec says secured, but anonymous call returned 200"))
            elif kind == "inject":
                if SQL_ERR.search(bd):
                    findings.append(Finding("API-SQLI-ERROR", "High", label, f"{name} -> database error text"))
    uniq = sorted(set(findings), key=lambda f: (f.severity != "High", f.rule, f.endpoint))
    return uniq, sent
