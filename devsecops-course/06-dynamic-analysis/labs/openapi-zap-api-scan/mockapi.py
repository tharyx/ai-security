"""A small mock REST API on 127.0.0.1 (weak and fixed variants) for the OpenAPI scan lab."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

USERS = {"alice": "alice-demo-pass", "bob": "bob-demo-pass"}  # FAKE
ORDERS = {1: {"owner": "alice", "item": "keyboard"}, 2: {"owner": "bob", "item": "monitor"}}
PRODUCTS = [("keyboard", 40), ("monitor", 200), ("mouse", 15)]


def make_handler(fixed: bool, tokens: dict):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def version_string(self):
            return "MockAPI"

        def reply(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def who(self):
            a = self.headers.get("Authorization", "")
            return tokens.get(a[7:]) if a.startswith("Bearer ") else None

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                d = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self.reply(400, {"error": "bad json"})
            if urlparse(self.path).path == "/api/v1/login":
                if USERS.get(d.get("username")) == d.get("password"):
                    tok = f"tok-{len(tokens) + 1}-{d['username']}"
                    tokens[tok] = d["username"]
                    return self.reply(200, {"token": tok})
                return self.reply(401, {"error": "invalid"})
            return self.reply(404, {"error": "not found"})

        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            who = self.who()
            if u.path == "/api/v1/products":
                if fixed and not who:  # weak API forgot the auth check here
                    return self.reply(401, {"error": "auth required"})
                con = sqlite3.connect(":memory:")
                con.execute("CREATE TABLE p (name TEXT, price INT)")
                con.executemany("INSERT INTO p VALUES (?,?)", PRODUCTS)
                s = q.get("search", "")
                try:
                    if fixed:
                        rows = con.execute("SELECT name, price FROM p WHERE name LIKE ?", (f"%{s}%",)).fetchall()
                    else:
                        rows = con.execute(f"SELECT name, price FROM p WHERE name LIKE '%{s}%'").fetchall()
                except sqlite3.Error as exc:
                    return self.reply(500, {"error": "internal error" if fixed else f"SQLite error: {exc}"})
                return self.reply(200, {"products": rows})
            if u.path.startswith("/api/v1/orders/"):
                if not who:
                    return self.reply(401, {"error": "auth required"})
                try:
                    oid = int(u.path.rsplit("/", 1)[1])
                except ValueError:
                    return self.reply(400, {"error": "bad id"})
                order = ORDERS.get(oid)
                if not order:
                    return self.reply(404, {"error": "no such order"})
                if fixed and order["owner"] != who:
                    return self.reply(403, {"error": "not your order"})  # BOLA fix: object-level check
                return self.reply(200, {"id": oid, **order})
            return self.reply(404, {"error": "not found"})

    return H


class MockApi:
    def __init__(self, fixed: bool = False):
        self.tokens: dict = {}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(fixed, self.tokens))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


@contextmanager
def running(fixed: bool = False):
    api = MockApi(fixed).start()
    try:
        yield api
    finally:
        api.stop()
