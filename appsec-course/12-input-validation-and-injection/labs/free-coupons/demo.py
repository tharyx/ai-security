import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coupons as c  # noqa: E402

for secure in (False, True):
    shop = c.Shop(secure)
    cart = c.new_cart()
    code, tries = c.brute_force(shop, "mallory", cart)
    print(f"== {'SECURE' if secure else 'VULNERABLE'} shop ==")
    print(f"brute force SAVE000-SAVE999: found={code} after {tries} requests")
    if code:
        for _ in range(9):
            shop.apply("mallory", cart, code)  # reuse and stack the same coupon
        print("after applying it 10 times, total =", cart["total"], "(was 1000.0)")
    real = shop._real_code
    cart2 = c.new_cart()
    print("secure-path test with the real code twice:",
          shop.apply("alice", cart2, real), shop.apply("alice", cart2, real), "total", cart2["total"])
    print()
