"""A tiny, dependency-free HTTP message toolkit for teaching API anatomy.

Everything here is a pure parser/formatter over bytes already in memory.
No sockets are opened, nothing is sent anywhere. It exists so a learner can
see exactly what a request line, headers and body look like, how a response
is built, what status codes mean, and the difference between a stateless API
call (a token on every request) and a stateful session (a server-side session
keyed by a cookie).

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

CRLF = "\r\n"

# What each status class means, so the lab can explain a code it has never
# seen before from its first digit.
STATUS_CLASS = {
    1: "Informational",
    2: "Success",
    3: "Redirection",
    4: "Client error",
    5: "Server error",
}

# A small set of codes an API author meets every day.
STATUS_TEXT = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    415: "Unsupported Media Type",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


def status_class(code: int) -> str:
    """Return the human name of a status class from its first digit."""
    return STATUS_CLASS.get(code // 100, "Unknown")


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str
    headers: dict  # lower-cased header name -> value
    body: str

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class HttpResponse:
    status: int
    version: str
    headers: dict
    body: str

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def _split_head_body(raw: str) -> tuple[list[str], str]:
    # Accept both CRLF (correct) and bare LF (what you often paste by hand).
    norm = raw.replace("\r\n", "\n")
    if "\n\n" in norm:
        head, body = norm.split("\n\n", 1)
    else:
        head, body = norm, ""
    return head.split("\n"), body


def parse_request(raw: str) -> HttpRequest:
    """Parse a raw HTTP request string into its parts.

    Example first line: ``GET /api/v1/orders/42 HTTP/1.1``
    """
    lines, body = _split_head_body(raw)
    if not lines or not lines[0].strip():
        raise ValueError("empty request: no request line")
    parts = lines[0].split()
    if len(parts) != 3:
        raise ValueError(f"malformed request line: {lines[0]!r}")
    method, target, version = parts
    headers = _parse_headers(lines[1:])
    return HttpRequest(method=method.upper(), target=target, version=version,
                       headers=headers, body=body)


def parse_response(raw: str) -> HttpResponse:
    """Parse a raw HTTP response string. First line: ``HTTP/1.1 200 OK``."""
    lines, body = _split_head_body(raw)
    if not lines or not lines[0].strip():
        raise ValueError("empty response: no status line")
    parts = lines[0].split(None, 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError(f"malformed status line: {lines[0]!r}")
    version = parts[0]
    status = int(parts[1])
    headers = _parse_headers(lines[1:])
    return HttpResponse(status=status, version=version, headers=headers, body=body)


def _parse_headers(lines: list[str]) -> dict:
    headers: dict = {}
    for line in lines:
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError(f"header without a colon: {line!r}")
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers


def build_response(status: int, headers: dict | None = None, body: str = "") -> str:
    """Build a raw HTTP/1.1 response string with a correct status line."""
    reason = STATUS_TEXT.get(status, "")
    out = [f"HTTP/1.1 {status} {reason}".rstrip()]
    headers = dict(headers or {})
    # A well-behaved server states the body length.
    if body and "content-length" not in {k.lower() for k in headers}:
        headers["Content-Length"] = str(len(body.encode()))
    for name, value in headers.items():
        out.append(f"{name}: {value}")
    return CRLF.join(out) + CRLF + CRLF + body


# --- Stateless vs stateful -------------------------------------------------
#
# A STATELESS API keeps no memory of past calls: the client proves who it is on
# EVERY request (here, an "Authorization: Bearer <token>" header). A STATEFUL
# design keeps a server-side session store and hands the client a cookie; the
# server looks the caller up by that cookie each time. The two classes below
# are deliberately minimal so a test can show the difference.


class StatelessApi:
    """Authorizes each call purely from the request's own Authorization header."""

    def __init__(self, valid_tokens: set[str]):
        self._tokens = set(valid_tokens)
        self.server_state_entries = 0  # stays zero: the point of "stateless"

    def handle(self, req: HttpRequest) -> HttpResponse:
        auth = req.header("authorization") or ""
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        if token in self._tokens:
            return parse_response(build_response(200, body="ok: " + req.target))
        return parse_response(build_response(401, {"WWW-Authenticate": "Bearer"}))


class StatefulApi:
    """Keeps a server-side session store; the client carries only a session id."""

    def __init__(self):
        self._sessions: dict = {}

    def login(self, user: str) -> HttpResponse:
        sid = secrets.token_hex(8)
        self._sessions[sid] = {"user": user}
        cookie = f"session={sid}; HttpOnly; Secure; SameSite=Lax; Path=/"
        return parse_response(build_response(200, {"Set-Cookie": cookie}, body="logged in"))

    @property
    def server_state_entries(self) -> int:
        return len(self._sessions)

    def handle(self, req: HttpRequest) -> HttpResponse:
        cookie = req.header("cookie") or ""
        sid = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                sid = part[len("session="):]
        sess = self._sessions.get(sid)
        if sess:
            return parse_response(build_response(200, body=f"ok: {sess['user']} -> {req.target}"))
        return parse_response(build_response(401, body="no valid session"))


@dataclass
class _Demo:
    notes: list = field(default_factory=list)


def make_fake_token() -> str:
    """Build a FAKE bearer token at runtime from pieces. Never a real secret."""
    return "FAKE-" + secrets.token_hex(6) + "-DEMO"
