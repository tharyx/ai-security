from aisec_lab import load_lab_module

p = load_lab_module(__file__, "pwstore")
FAST = 2_000  # small iteration count keeps tests quick; the policy constant is checked separately
USERS = {"asha": "monsoon2024", "meena": "monsoon2024", "ravi": "letmein", "joe": "correct horse battery staple"}


def test_unsalted_md5_reveals_shared_passwords_and_is_cracked():
    legacy = {u: p.md5_unsalted(pw) for u, pw in USERS.items()}
    assert ["asha", "meena"] in p.identical_hash_groups(legacy)
    cracked, _, _ = p.dictionary_attack(legacy, p.LAB_WORDLIST)
    assert cracked == {"asha": "monsoon2024", "meena": "monsoon2024", "ravi": "letmein"}


def test_salted_hashes_differ_for_the_same_password():
    a, b = p.pbkdf2_hash("monsoon2024", FAST), p.pbkdf2_hash("monsoon2024", FAST)
    assert a != b
    modern = {u: p.pbkdf2_hash(pw, FAST) for u, pw in USERS.items()}
    assert p.identical_hash_groups(modern) == []


def test_pbkdf2_and_scrypt_verify_correctly():
    h = p.pbkdf2_hash("long lab passphrase", FAST)
    assert p.verify("long lab passphrase", h) and not p.verify("wrong", h)
    s = p.scrypt_hash("long lab passphrase", n=2 ** 12)
    assert p.verify("long lab passphrase", s) and not p.verify("wrong", s)


def test_pepper_blocks_cracking_from_a_stolen_database_alone():
    pepper = p.make_fake_pepper()
    stored = {"ravi": p.pbkdf2_hash("letmein", FAST, pepper=pepper)}
    assert p.dictionary_attack(stored, p.LAB_WORDLIST, pepper=None)[0] == {}
    assert p.dictionary_attack(stored, p.LAB_WORDLIST, pepper=pepper)[0] == {"ravi": "letmein"}


def test_slow_hash_costs_far_more_per_guess_than_md5():
    legacy = {"u": p.md5_unsalted("not-in-list")}
    modern = {"u": p.pbkdf2_hash("not-in-list", 50_000)}
    _, _, t_fast = p.dictionary_attack(legacy, p.LAB_WORDLIST)
    _, _, t_slow = p.dictionary_attack(modern, p.LAB_WORDLIST)
    assert t_slow > 20 * t_fast


def test_upgrade_on_login_replaces_legacy_hash_only_after_success():
    store = p.UserStore(iterations=FAST)
    store.users = {"ravi": p.md5_unsalted("letmein"), "asha": p.md5_unsalted("monsoon2024")}
    assert not store.login("ravi", "wrong") and store.users["ravi"].startswith("$md5$")
    assert store.login("ravi", "letmein")
    assert store.users["ravi"].startswith("$pbkdf2-sha256$") and store.upgraded == ["ravi"]
    assert store.login("ravi", "letmein")  # still works after the upgrade
    assert store.users["asha"].startswith("$md5$")


def test_low_iteration_hash_is_flagged_for_rehash():
    assert p.needs_rehash(p.pbkdf2_hash("x", 1_000), 600_000)
    assert not p.needs_rehash(p.pbkdf2_hash("x", 2_000), 2_000)
    assert p.PBKDF2_POLICY_ITERATIONS >= 600_000


def test_policy_prefers_length_and_blocklist_over_composition():
    assert p.check_password_policy("Tr0ub4dor&3") != []  # complex but short without MFA
    assert p.check_password_policy("Tr0ub4dor&3", mfa=True) == []
    assert "blocklist" in " ".join(p.check_password_policy("password123", mfa=True))
    assert p.check_password_policy("correct horse battery staple") == []
