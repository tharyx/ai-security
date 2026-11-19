"""One runnable mini-demo per OWASP API Security Top 10 2023 item, vulnerable vs secure,
plus the 2019 -> 2023 mapping as data.

Each demo is a pair of tiny functions. run_all() runs the same attack against both and
reports whether it worked. Deeper labs for some items live in chapters 10-12 and 13.
Everything is in-process; secrets are FAKE and built at runtime.
"""

from __future__ import annotations

import ipaddress
import secrets
from urllib.parse import urlparse

MAP_2019_TO_2023 = {
    "API1:2019 Broken Object Level Authorization": "API1:2023 Broken Object Level Authorization",
    "API2:2019 Broken User Authentication": "API2:2023 Broken Authentication",
    "API3:2019 Excessive Data Exposure": "API3:2023 Broken Object Property Level Authorization",
    "API4:2019 Lack of Resources & Rate Limiting": "API4:2023 Unrestricted Resource Consumption",
    "API5:2019 Broken Function Level Authorization": "API5:2023 Broken Function Level Authorization",
    "API6:2019 Mass Assignment": "API3:2023 Broken Object Property Level Authorization",
    "API7:2019 Security Misconfiguration": "API8:2023 Security Misconfiguration",
    "API8:2019 Injection": None,  # dropped as its own item; still covered by the web Top 10
    "API9:2019 Improper Assets Management": "API9:2023 Improper Inventory Management",
    "API10:2019 Insufficient Logging & Monitoring": None,  # dropped
}
NEW_IN_2023 = ["API6:2023 Unrestricted Access to Sensitive Business Flows", "API7:2023 Server Side Request Forgery",
               "API10:2023 Unsafe Consumption of APIs"]

# ------------------------------------------------------------------ API1 BOLA
INVOICES = {1: {"owner": "alice", "amount": 120}, 2: {"owner": "bob", "amount": 9900}}


def api1(secure, user, invoice_id):
    inv = INVOICES.get(invoice_id)
    if inv and secure and inv["owner"] != user:
        return None
    return inv


# ------------------------------------------------------------------ API2 Broken Authentication
class Login:
    def __init__(self, secure):
        self.secure, self.fails, self.pin = secure, 0, f"{secrets.randbelow(1000):03d}"

    def attempt(self, pin):
        if self.secure and self.fails >= 5:
            return "locked"
        if pin == self.pin:
            return "ok"
        self.fails += 1
        return "bad"


def api2_attack(secure) -> bool:
    login = Login(secure)
    return any(login.attempt(f"{i:03d}") == "ok" for i in range(1000))


# ------------------------------------------------------------------ API3 BOPLA
USER = {"id": 7, "name": "alice", "password_hash": "FAKE-hash", "is_admin": False}


def api3_read(secure):
    return {k: USER[k] for k in ("id", "name")} if secure else dict(USER)


def api3_write(secure, body):
    user = dict(USER)
    user.update({k: v for k, v in body.items() if (not secure or k in {"name"})})
    return user


# ------------------------------------------------------------------ API4 Unrestricted Resource Consumption
ROWS = list(range(100_000))


def api4_list(secure, limit):
    if secure:
        limit = max(1, min(int(limit), 100))
    return ROWS[:limit]


# ------------------------------------------------------------------ API5 BFLA
def api5_delete_user(secure, caller_role):
    if secure and caller_role != "admin":
        return 403
    return 204


# ------------------------------------------------------------------ API6 Sensitive business flows
class Drop:
    """Limited-edition sneaker drop: 10 pairs."""

    def __init__(self, secure):
        self.secure, self.stock, self.bought = secure, 10, {}

    def buy(self, account, device, velocity_per_min):
        if self.secure:
            if self.bought.get(account, 0) >= 1 or velocity_per_min > 5 or device == "headless":
                return False
        if self.stock == 0:
            return False
        self.stock -= 1
        self.bought[account] = self.bought.get(account, 0) + 1
        return True


def api6_bot(secure) -> int:
    d = Drop(secure)
    return sum(d.buy("scalper", "headless", 600) for _ in range(50))


# ------------------------------------------------------------------ API7 SSRF
CANARY = "FAKE-METADATA-" + secrets.token_hex(3)
NET = {"hooks.partner.example": ("93.184.216.34", "ok"), "169.254.169.254": ("169.254.169.254", CANARY)}


def api7_webhook_test(secure, url):
    host = urlparse(url).hostname
    ip, body = NET.get(host, (host, "404"))
    if secure:
        a = ipaddress.ip_address(ip)
        if urlparse(url).scheme != "https" or a.is_private or a.is_link_local or a.is_loopback:
            return "blocked"
    return body


# ------------------------------------------------------------------ API8 Security Misconfiguration
def api8_error(secure, trigger):
    try:
        return {"total": 100 / int(trigger)}
    except Exception as e:
        if secure:
            return {"error": "internal error", "id": "err-1234"}
        return {"error": repr(e), "trace": "File /srv/app/billing.py line 88, Django 3.2.4 DEBUG=True"}


# ------------------------------------------------------------------ API9 Improper Inventory Management
DOCUMENTED = {"GET /api/v2/users/{id}", "POST /api/v2/login"}
DEPLOYED_VULN = DOCUMENTED | {"GET /api/v1/users/{id}", "POST /api/v1/login", "GET /api/v2/debug/env"}
DEPLOYED_SECURE = set(DOCUMENTED)


def api9_undocumented(deployed):
    return sorted(deployed - DOCUMENTED)


# ------------------------------------------------------------------ API10 Unsafe Consumption of APIs
def third_party_address_api(postcode):
    """A compromised or malicious partner API."""
    return {"city": "Bengaluru'; DROP TABLE orders; --", "redirect": "http://169.254.169.254/"}


def api10_consume(secure, postcode):
    data = third_party_address_api(postcode)
    if not secure:
        return f"UPDATE orders SET city = '{data['city']}'", data.get("redirect")  # trusted blindly
    city = data.get("city", "")
    if not isinstance(city, str) or not city.replace(" ", "").isalpha() or len(city) > 60:
        return "rejected: invalid city from upstream", None
    return ("UPDATE orders SET city = ?", city), None  # never follow upstream redirects


# ------------------------------------------------------------------ run all

def run_all() -> list[tuple[str, bool, bool]]:
    """(item, attack works on vulnerable, attack works on secure)"""
    out = []
    out.append(("API1 BOLA", api1(False, "alice", 2) is not None, api1(True, "alice", 2) is not None))
    out.append(("API2 Broken Authentication", api2_attack(False), api2_attack(True)))
    out.append(("API3 BOPLA", "password_hash" in api3_read(False) and api3_write(False, {"is_admin": True})["is_admin"],
                "password_hash" in api3_read(True) or api3_write(True, {"is_admin": True})["is_admin"]))
    out.append(("API4 Unrestricted Resource Consumption", len(api4_list(False, 10**6)) > 1000,
                len(api4_list(True, 10**6)) > 1000))
    out.append(("API5 BFLA", api5_delete_user(False, "user") == 204, api5_delete_user(True, "user") == 204))
    out.append(("API6 Sensitive Business Flows", api6_bot(False) >= 10, api6_bot(True) >= 10))
    out.append(("API7 SSRF", api7_webhook_test(False, "http://169.254.169.254/latest") == CANARY,
                api7_webhook_test(True, "http://169.254.169.254/latest") == CANARY))
    out.append(("API8 Security Misconfiguration", "trace" in api8_error(False, "0"), "trace" in api8_error(True, "0")))
    out.append(("API9 Improper Inventory Management", bool(api9_undocumented(DEPLOYED_VULN)),
                bool(api9_undocumented(DEPLOYED_SECURE))))
    v_sql, v_redirect = api10_consume(False, "560001")
    s_sql, s_redirect = api10_consume(True, "560001")
    out.append(("API10 Unsafe Consumption of APIs", "DROP TABLE" in str(v_sql) and bool(v_redirect),
                "DROP TABLE" in str(s_sql) or bool(s_redirect)))
    return out
