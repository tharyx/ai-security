from aisec_lab import load_lab_module

c = load_lab_module(__file__, "hashcrack")


def test_unsalted_md5_leaks_password_reuse():
    # identical passwords give identical hashes: reuse is visible at a glance
    assert c.md5_hex("sunshine") == c.md5_hex("sunshine")


def test_dictionary_attack_cracks_many_unsalted_hashes_at_once():
    leaked = {"u1": c.md5_hex("sunshine"), "u2": c.md5_hex("dragon"),
              "u3": c.md5_hex("bluecat")}
    cracked = c.dictionary_attack(leaked, c.TINY_DICTIONARY)
    assert cracked == {"u1": "sunshine", "u2": "dragon"}  # bluecat not in list


def test_dictionary_attack_works_on_sha1_too():
    leaked = {"u": c.sha1_hex("dragon")}
    assert c.dictionary_attack(leaked, c.TINY_DICTIONARY, hash_fn=c.sha1_hex) == {"u": "dragon"}


def test_brute_force_cracks_a_short_password():
    pw, tries = c.brute_force(c.md5_hex("abc"), max_len=3)
    assert pw == "abc" and tries > 26


def test_brute_force_keyspace_is_capped():
    try:
        c.brute_force(c.md5_hex("abcde"), max_len=5)
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_combinations_attack_cracks_word_plus_suffix():
    pw, _ = c.combinations_attack(c.md5_hex("summer2024"))
    assert pw == "summer2024"
    pw2, _ = c.combinations_attack(c.md5_hex("bluecat"))
    assert pw2 == "bluecat"


def test_salted_pbkdf2_gives_unique_hashes_and_defeats_table_lookup():
    h1 = c.pbkdf2_hash("sunshine", iterations=1000)
    h2 = c.pbkdf2_hash("sunshine", iterations=1000)
    assert h1 != h2  # different random salts
    assert c.pbkdf2_verify("sunshine", h1) and not c.pbkdf2_verify("dragon", h1)
    # the precomputed MD5 table matches nothing
    assert c.dictionary_attack({"u": h1.split("$")[-1]}, c.TINY_DICTIONARY) == {}


def test_scrypt_round_trip():
    h = c.scrypt_hash("dragon", n=2**10)
    assert c.scrypt_verify("dragon", h) and not c.scrypt_verify("sunshine", h)


def test_slow_hash_is_far_slower_per_guess_than_md5():
    md5_rate = c.guesses_per_second(c.md5_hex, 0.1)
    pbkdf2_rate = c.guesses_per_second(lambda p: c.pbkdf2_hash(p, b"0" * 16, 20_000), 0.1)
    assert md5_rate > 100 * pbkdf2_rate
