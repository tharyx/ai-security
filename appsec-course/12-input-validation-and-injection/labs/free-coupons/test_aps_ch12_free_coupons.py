from aisec_lab import load_lab_module

c = load_lab_module(__file__, "coupons")


def test_predictable_code_is_brute_forced_without_any_limit():
    shop = c.Shop(secure=False)
    code, tries = c.brute_force(shop, "mallory", c.new_cart())
    assert code == shop._real_code and tries <= 1000


def test_reusing_and_stacking_coupon_makes_order_almost_free_on_vulnerable_shop():
    shop = c.Shop(secure=False)
    cart = c.new_cart()
    for _ in range(10):
        shop.apply("mallory", cart, shop._real_code)
    assert cart["total"] < 30  # 1000 * 0.7**10 = 28.25


def test_secure_shop_locks_out_after_five_wrong_guesses():
    shop = c.Shop(secure=True)
    code, tries = c.brute_force(shop, "mallory", c.new_cart())
    assert code is None and tries == 6
    assert shop.apply("mallory", c.new_cart(), shop._real_code)[0] == 429


def test_lockout_window_expires_with_clock():
    t = [0]
    shop = c.Shop(secure=True, clock=lambda: t[0])
    for _ in range(5):
        shop.apply("m", c.new_cart(), "WRONG")
    assert shop.apply("m", c.new_cart(), "WRONG")[0] == 429
    t[0] = 901
    assert shop.apply("m", c.new_cart(), "WRONG")[0] == 404


def test_secure_shop_single_use_one_coupon_and_floor():
    shop = c.Shop(secure=True)
    cart = c.new_cart()
    assert shop.apply("alice", cart, shop._real_code) == (200, 700.0)
    assert shop.apply("alice", cart, shop._real_code)[0] == 409
    assert shop.apply("alice", c.new_cart(), shop._real_code)[1] == "coupon already used"


def test_secure_codes_are_long_and_random():
    codes = {c.Shop(secure=True)._real_code for _ in range(5)}
    assert len(codes) == 5 and all(len(x) == 16 for x in codes)
