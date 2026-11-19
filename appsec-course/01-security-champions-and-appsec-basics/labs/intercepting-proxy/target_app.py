"""A tiny checkout app used as the proxy target. In-process only.

VulnerableCheckout trusts things the browser sends (a hidden price field, a role cookie)
and has no limit on coupon guesses. SecureCheckout keeps that state on the server.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlsplit

CATALOG = {"7": ("Noise-cancelling headphones", 499.00)}
COUPON = "WELCOME" + "42"  # a toy coupon code


def _form(body: str) -> dict:
    return {k: v[0] for k, v in parse_qs(body or "", keep_blank_values=True).items()}


def _cookies(headers: dict) -> dict:
    out = {}
    for part in headers.get("cookie", "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out


class VulnerableCheckout:
    def __init__(self) -> None:
        self.charges: list = []
        self.sessions: dict = {}
        self.coupon_attempts = 0

    def handle(self, method: str, target: str, headers: dict, body: str):
        headers = {k.lower(): v for k, v in headers.items()}
        path = urlsplit(target).path
        if path == "/" and method == "GET":
            return self.index()
        if path == "/product/7":
            if method != "GET":
                return 405, {"Allow": "GET"}, "method not allowed"
            name, price = CATALOG["7"]
            return 200, {"Content-Type": "text/html"}, (
                f"<h2>{name}</h2><form method=POST action=/checkout>"
                f"<input type=hidden name=sku value=7><input type=hidden name=price value={price:.2f}>"
                "<input name=qty value=1></form>")
        if path == "/checkout" and method == "POST":
            return self.checkout(_form(body))
        if path == "/admin":
            return self.admin(headers)
        if path == "/coupon" and method == "POST":
            return self.coupon(_form(body))
        if path == "/old-cart":
            return 302, {"Location": "/product/7"}, ""
        return 404, {"Content-Type": "text/plain"}, "not found"

    def index(self):
        # VULN: the role is stored in a cookie the browser (and any proxy) can edit.
        return 200, {"Content-Type": "text/html", "Set-Cookie": "role=customer; Path=/"}, "<h1>Shop</h1>"

    def checkout(self, form: dict):
        # VULN: the price comes from the client. A proxy can change it in flight.
        total = float(form.get("price", "0")) * int(form.get("qty", "1"))
        self.charges.append(total)
        return 200, {"Content-Type": "text/plain"}, f"charged {total:.2f}"

    def admin(self, headers: dict):
        # VULN: authorization decided by a cookie the client controls.
        if _cookies(headers).get("role") == "admin":
            return 200, {"Content-Type": "text/plain"}, "admin panel: 1,204 orders"
        return 403, {"Content-Type": "text/plain"}, "forbidden"

    def coupon(self, form: dict):
        # VULN: unlimited guesses, and the response length differs for the right code.
        self.coupon_attempts += 1
        if form.get("code") == COUPON:
            return 200, {"Content-Type": "text/plain"}, "coupon applied: 10% off your next order"
        return 200, {"Content-Type": "text/plain"}, "invalid"


class SecureCheckout(VulnerableCheckout):
    MAX_COUPON_TRIES = 5

    def index(self):
        sid = secrets.token_hex(8)
        self.sessions[sid] = {"role": "customer"}  # the role lives on the server
        return 200, {"Content-Type": "text/html",
                     "Set-Cookie": f"session={sid}; Path=/; HttpOnly; Secure; SameSite=Lax"}, "<h1>Shop</h1>"

    def checkout(self, form: dict):
        sku, qty = form.get("sku", ""), form.get("qty", "")
        if sku not in CATALOG or not qty.isdigit() or not 1 <= int(qty) <= 10:
            return 400, {"Content-Type": "text/plain"}, "bad request"
        total = CATALOG[sku][1] * int(qty)  # price looked up on the server; client 'price' ignored
        self.charges.append(total)
        return 200, {"Content-Type": "text/plain"}, f"charged {total:.2f}"

    def admin(self, headers: dict):
        sess = self.sessions.get(_cookies(headers).get("session", ""))
        if sess and sess["role"] == "admin":  # role kept server-side
            return 200, {"Content-Type": "text/plain"}, "admin panel"
        return 403, {"Content-Type": "text/plain"}, "forbidden"

    def coupon(self, form: dict):
        self.coupon_attempts += 1
        if self.coupon_attempts > self.MAX_COUPON_TRIES:
            return 429, {"Content-Type": "text/plain", "Retry-After": "600"}, "too many attempts"
        if form.get("code") == COUPON:
            return 200, {"Content-Type": "text/plain"}, "coupon applied: 10% off your next order"
        return 200, {"Content-Type": "text/plain"}, "invalid"
