"""A mini intercepting proxy in the style of Burp Suite, working in-process.

It teaches the parts of Burp you use every day:
- raw HTTP request/response parsing and serialization (what you see in the Proxy tab),
- intercept hooks that edit a request before it reaches the app (Proxy > Intercept),
- match-and-replace rules,
- HTTP history,
- Repeater (resend an edited copy of a past request),
- Intruder "Sniper" (one payload position, a list of payloads, compare status and length).

No socket is opened: the proxy calls ``app.handle(method, target, headers, body)`` directly.
Only test systems you own or have written permission to test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from http import HTTPStatus

CRLF = "\r\n"


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str = "HTTP/1.1"
    headers: list = field(default_factory=list)  # list of (name, value): order and duplicates matter
    body: str = ""

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return default

    def set_header(self, name: str, value: str) -> None:
        self.headers = [(k, v) for k, v in self.headers if k.lower() != name.lower()] + [(name, value)]

    def to_raw(self) -> str:
        hdrs = [(k, v) for k, v in self.headers if k.lower() != "content-length"]
        if self.body or self.method in ("POST", "PUT", "PATCH"):
            hdrs.append(("Content-Length", str(len(self.body.encode()))))  # always recomputed
        lines = [f"{self.method} {self.target} {self.version}"] + [f"{k}: {v}" for k, v in hdrs]
        return CRLF.join(lines) + CRLF + CRLF + self.body


@dataclass
class HttpResponse:
    status: int
    headers: list = field(default_factory=list)
    body: str = ""
    version: str = "HTTP/1.1"

    @property
    def reason(self) -> str:
        try:
            return HTTPStatus(self.status).phrase
        except ValueError:
            return "Unknown"

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return default

    def to_raw(self) -> str:
        hdrs = [(k, v) for k, v in self.headers if k.lower() != "content-length"]
        hdrs.append(("Content-Length", str(len(self.body.encode()))))
        lines = [f"{self.version} {self.status} {self.reason}"] + [f"{k}: {v}" for k, v in hdrs]
        return CRLF.join(lines) + CRLF + CRLF + self.body


def _split(raw: str):
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"malformed header line: {line!r}")
        headers.append((name.strip(), value.strip()))
    return lines[0], headers, body


def parse_request(raw: str) -> HttpRequest:
    start, headers, body = _split(raw)
    parts = start.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise ValueError(f"bad request line: {start!r}")
    return HttpRequest(parts[0].upper(), parts[1], parts[2], headers, body)


def parse_response(raw: str) -> HttpResponse:
    start, headers, body = _split(raw)
    version, code, _reason = start.split(" ", 2)
    return HttpResponse(int(code), headers, body, version)


def status_class(code: int) -> str:
    return {1: "1xx Informational", 2: "2xx Success", 3: "3xx Redirection",
            4: "4xx Client error", 5: "5xx Server error"}.get(code // 100, "invalid")


class InterceptingProxy:
    def __init__(self, app) -> None:
        self.app = app
        self.request_hooks: list = []
        self.response_hooks: list = []
        self.match_replace: list = []  # (regex, replacement) applied to the raw request
        self.history: list = []        # (HttpRequest, HttpResponse) like Burp's HTTP history

    def on_request(self, fn) -> None:
        self.request_hooks.append(fn)

    def on_response(self, fn) -> None:
        self.response_hooks.append(fn)

    def add_match_replace(self, pattern: str, repl: str) -> None:
        self.match_replace.append((re.compile(pattern), repl))

    def send(self, raw_request: str) -> str:
        for rx, repl in self.match_replace:
            raw_request = rx.sub(repl, raw_request)
        req = parse_request(raw_request)
        for hook in self.request_hooks:
            req = hook(req) or req
        status, hdrs, body = self.app.handle(req.method, req.target, dict(req.headers), req.body)
        resp = HttpResponse(status, list(hdrs.items()), body)
        for hook in self.response_hooks:
            resp = hook(resp) or resp
        self.history.append((req, resp))
        return resp.to_raw()

    def repeater(self, index: int, edit) -> HttpResponse:
        """Copy history[index], let `edit(req)` change it, send it again."""
        req = replace(self.history[index][0], headers=list(self.history[index][0].headers))
        req = edit(req) or req
        self.send(req.to_raw())
        return self.history[-1][1]

    def intruder_sniper(self, template: str, payloads: list) -> list:
        """One position marked with §...§. Returns (payload, status, length) rows."""
        if template.count("§") != 2:
            raise ValueError("template needs exactly one §position§")
        rows = []
        for p in payloads:
            raw = re.sub(r"§[^§]*§", p, template)
            resp = parse_response(self.send(raw))
            rows.append((p, resp.status, len(resp.body)))
        return rows
