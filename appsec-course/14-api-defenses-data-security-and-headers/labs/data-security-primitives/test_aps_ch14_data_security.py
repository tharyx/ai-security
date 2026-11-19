import os
import sqlite3

import pytest
from aisec_lab import load_lab_module

d = load_lab_module(__file__, "datasec")


def test_encoding_is_reversible_without_any_key():
    for kind, val in d.encode_all("secret=FAKE-value").items():
        assert d.decode(kind, val) == "secret=FAKE-value"


def test_html_escaping_neutralizes_markup_but_only_for_html():
    out = d.escape_for("html", '<img src=x onerror="alert(1)">')
    assert "<" not in out and '"' not in out
    js = d.escape_for("js_string", "</script><b>")
    assert "</script>" not in js and js.startswith('"')


def test_string_built_sql_leaks_all_rows_bind_variables_do_not():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (name TEXT, role TEXT)")
    db.executemany("INSERT INTO users VALUES (?, ?)", [("asha", "user"), ("ravi", "admin")])
    inj = "x' OR '1'='1"
    assert len(d.sql_lookup(db, inj, safe=False)) == 2
    assert d.sql_lookup(db, inj, safe=True) == []


def test_plain_hash_of_pin_is_reversed_but_hmac_needs_the_key():
    assert d.reverse_low_entropy_hash(d.sha256_hex("0731")) == "0731"
    tok = d.keyed_pseudonym(os.urandom(32), "0731")
    assert d.reverse_low_entropy_hash(tok) is None


def test_hmac_tag_detects_tampering():
    k = os.urandom(32)
    tag = d.integrity_tag(k, b'{"amount": 10}')
    assert d.verify_tag(k, b'{"amount": 10}', tag)
    assert not d.verify_tag(k, b'{"amount": 99}', tag)


def test_toy_aead_roundtrip_random_nonce_and_tamper_detection():
    c = d.ToyAEAD(os.urandom(32))
    a, b = c.encrypt(b"hello", b"row1"), c.encrypt(b"hello", b"row1")
    assert a != b  # fresh nonce each time
    assert c.decrypt(a, b"row1") == b"hello"
    flipped = bytearray(a); flipped[20] ^= 1
    with pytest.raises(d.IntegrityError):
        c.decrypt(bytes(flipped), b"row1")
    with pytest.raises(d.IntegrityError):
        c.decrypt(a, b"row2")


def test_plaintext_store_leaks_pan_in_dump_encrypted_store_does_not():
    plain = d.CardStore(encrypted=False)
    kr = d.KeyRing(); kr.rotate()
    safe = d.CardStore(encrypted=True, keyring=kr)
    pan = d.fake_pan(7)
    plain.add("c1", pan); safe.add("c1", pan)
    assert pan in plain.dump()
    assert pan not in safe.dump() and safe.get_pan("c1") == pan


def test_ciphertext_swapped_between_rows_is_rejected():
    kr = d.KeyRing(); kr.rotate()
    s = d.CardStore(encrypted=True, keyring=kr)
    s.add("c1", d.fake_pan(1)); s.add("c2", d.fake_pan(2))
    c1 = s.db.execute("SELECT pan FROM cards WHERE customer_id='c1'").fetchone()[0]
    s.db.execute("UPDATE cards SET pan=? WHERE customer_id='c2'", (c1,))
    with pytest.raises(d.IntegrityError):
        s.get_pan("c2")


def test_key_rotation_rewraps_and_old_key_can_be_retired():
    kr = d.KeyRing(); kr.rotate()
    s = d.CardStore(encrypted=True, keyring=kr)
    s.add("c1", d.fake_pan(3))
    assert s.rotate_and_rewrap() == 1 and kr.active == "k2"
    del kr.keys["k1"]
    assert s.get_pan("c1") == d.fake_pan(3)


def test_short_keys_are_refused():
    with pytest.raises(ValueError):
        d.ToyAEAD(b"short")
