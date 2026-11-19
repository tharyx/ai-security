"""An in-process toy REST API plus a curl command parser/builder.

This teaches the CASP 2 lines "Understanding an API Language (Endpoints,
Verbs, and State)", "Understanding cURL Command" and "Performing CRUD
Operations Using API". Nothing listens on a socket: the API is a single
``handle(method, path, headers, body)`` function over an in-memory store, and
``parse_curl`` / ``build_curl`` turn a request into and out of a curl command
line so you can read the verbs and state transitions directly.

Only test systems you own or have written permission to test.
"""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field


@dataclass
class Response:
    status: int
    body: object = None
    headers: dict = field(default_factory=dict)


class ToyApi:
    """CRUD over /api/v1/items. Verbs map to create/read/update/delete."""

    def __init__(self):
        self._items: dict = {}
        self._next = 1

    def handle(self, method: str, path: str, headers: dict | None = None,
               body: object = None) -> Response:
        headers = headers or {}
        method = method.upper()
        parts = [p for p in path.split("?")[0].split("/") if p]
        # expect: api / v1 / items [ / id ]
        if parts[:3] != ["api", "v1", "items"]:
            return Response(404, {"error": "not found"})
        item_id = parts[3] if len(parts) > 3 else None

        if method == "GET" and item_id is None:
            return Response(200, list(self._items.values()))
        if method == "POST" and item_id is None:
            return self._create(body)
        if item_id is not None:
            try:
                key = int(item_id)
            except ValueError:
                return Response(400, {"error": "id must be an integer"})
            if method == "GET":
                return self._read(key)
            if method == "PUT":
                return self._update(key, body)
            if method == "DELETE":
                return self._delete(key)
        return Response(405, {"error": "method not allowed"})

    def _create(self, body):
        data = _as_dict(body)
        if data is None or "name" not in data:
            return Response(400, {"error": "name is required"})
        item = {"id": self._next, "name": data["name"]}
        self._items[self._next] = item
        self._next += 1
        return Response(201, item, {"Location": f"/api/v1/items/{item['id']}"})

    def _read(self, key):
        item = self._items.get(key)
        return Response(200, item) if item else Response(404, {"error": "no such item"})

    def _update(self, key, body):
        if key not in self._items:
            return Response(404, {"error": "no such item"})
        data = _as_dict(body) or {}
        self._items[key]["name"] = data.get("name", self._items[key]["name"])
        return Response(200, self._items[key])

    def _delete(self, key):
        if self._items.pop(key, None) is None:
            return Response(404, {"error": "no such item"})
        return Response(204)


def _as_dict(body):
    if body is None:
        return None
    if isinstance(body, dict):
        return body
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


# --- curl parser / builder -------------------------------------------------
@dataclass
class CurlRequest:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    data: str | None = None


def parse_curl(command: str) -> CurlRequest:
    """Parse a (subset of a) curl command line into method, url, headers, data."""
    tokens = shlex.split(command)
    if not tokens or tokens[0] != "curl":
        raise ValueError("not a curl command")
    method = None
    url = None
    headers: dict = {}
    data = None
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-X", "--request"):
            method = tokens[i + 1]
            i += 2
        elif tok in ("-H", "--header"):
            name, _, value = tokens[i + 1].partition(":")
            headers[name.strip()] = value.strip()
            i += 2
        elif tok in ("-d", "--data", "--data-raw"):
            data = tokens[i + 1]
            i += 2
        elif tok.startswith("-"):
            i += 1  # ignore flags we do not model
        else:
            url = tok
            i += 1
    if url is None:
        raise ValueError("no URL in curl command")
    if method is None:
        method = "POST" if data is not None else "GET"
    return CurlRequest(method=method.upper(), url=url, headers=headers, data=data)


def build_curl(req: CurlRequest) -> str:
    """Build a curl command line from a CurlRequest."""
    parts = ["curl", "-X", req.method]
    for name, value in req.headers.items():
        parts += ["-H", shlex.quote(f"{name}: {value}")]
    if req.data is not None:
        parts += ["-d", shlex.quote(req.data)]
    parts.append(shlex.quote(req.url))
    return " ".join(parts)


def call_with_curl(api: ToyApi, command: str) -> Response:
    """Parse a curl command and run it against the in-process API."""
    req = parse_curl(command)
    path = req.url.split("://", 1)[-1]
    path = "/" + path.split("/", 1)[1] if "/" in path else "/"
    return api.handle(req.method, path, req.headers, req.data)
