"""Getting free coupons without knowing the coupon code (business logic + brute force).

Vulnerable shop:
  - coupon codes are predictable: "SAVE" + 3 digits;
  - no limit on wrong guesses;
  - a coupon can be applied many times and coupons stack;
  - the total can drop to zero (free order).
Secure shop:
  - 16-char random codes (secrets), generated at runtime;
  - 5 wrong guesses per account per 15 minutes, then 429 (simulated clock);
  - one use per account, one coupon per order, server-side minimum total.
"""

from __future__ import annotations

import secrets
import string


class Shop:
    def __init__(self, secure: bool, clock=None):
        self.secure = secure
        self.now = clock or (lambda: 0)
        self.fails: dict[str, list[float]] = {}
        self.used: set[tuple[str, str]] = set()
        if secure:
            alphabet = string.ascii_uppercase + string.digits
            code = "".join(secrets.choice(alphabet) for _ in range(16))
        else:
            code = "SAVE" + f"{secrets.randbelow(1000):03d}"  # tiny keyspace
        self.coupons = {code: 30}  # percent off
        self._real_code = code  # for tests only

    def apply(self, account: str, cart: dict, code: str):
        if self.secure:
            recent = [t for t in self.fails.get(account, []) if self.now() - t < 900]
            self.fails[account] = recent
            if len(recent) >= 5:
                return 429, "too many attempts, try later"
            if cart.get("coupons"):
                return 409, "one coupon per order"
            if (account, code) in self.used:
                return 409, "coupon already used"
        if code not in self.coupons:
            self.fails.setdefault(account, []).append(self.now())
            return 404, "invalid coupon"
        cart.setdefault("coupons", []).append(code)
        pct = 100 - self.coupons[code]
        cart["total"] = round(cart["total"] * pct / 100, 2)
        if self.secure:
            self.used.add((account, code))
            cart["total"] = max(cart["total"], cart["subtotal"] * 0.5)  # business floor
        return 200, cart["total"]


def brute_force(shop: Shop, account: str, cart: dict, max_tries: int = 1000):
    """Try SAVE000..SAVE999 like an Intruder 'numbers' payload."""
    for i in range(max_tries):
        status, _ = shop.apply(account, cart, f"SAVE{i:03d}")
        if status == 200:
            return f"SAVE{i:03d}", i + 1
        if status == 429:
            return None, i + 1
    return None, max_tries


def new_cart(amount=1000.0) -> dict:
    return {"subtotal": amount, "total": amount}
