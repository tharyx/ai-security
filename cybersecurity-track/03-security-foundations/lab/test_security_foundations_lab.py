"""Tests for the password storage and phishing analyzer labs.

Run from the repository root:
    .venv/Scripts/python -m pytest cybersecurity-track/03-security-foundations -v
"""

from pathlib import Path

from aisec_lab import load_lab_module

ps = load_lab_module(__file__, "password_storage")
pa = load_lab_module(__file__, "phishing_analyzer")

SAMPLES = Path(__file__).resolve().parent / "samples"
WORDLIST = ps.load_wordlist((SAMPLES / "wordlist.txt").read_text())
USERS = {"asha": "welcome1", "ben": "welcome1", "chen": "Tr0ub4dor&3-synthetic", "dina": "dragon"}
FAST = 1000  # low iteration count only to keep tests quick


def recs(kind):
    if kind == "plain":
        return [ps.store_plain(u, p) for u, p in USERS.items()]
    if kind == "md5":
        return [ps.store_md5(u, p) for u, p in USERS.items()]
    return [ps.store_pbkdf2(u, p, iterations=FAST) for u, p in USERS.items()]


def eml(name):
    return pa.analyze((SAMPLES / name).read_text())


# ---------- password storage ----------

def test_plain_storage_reveals_password_directly():
    assert recs("plain")[0].stored == "welcome1"


def test_md5_is_cracked_for_weak_passwords_but_not_strong_ones():
    cracked = ps.dictionary_attack(recs("md5"), WORDLIST)["cracked"]
    assert cracked == {"asha": "welcome1", "ben": "welcome1", "dina": "dragon"}
    assert "chen" not in cracked  # strong password not in the list


def test_unsalted_md5_shows_duplicate_passwords():
    assert ps.duplicate_hashes(recs("md5")) == [["asha", "ben"]]


def test_salted_pbkdf2_hides_duplicate_passwords():
    assert ps.duplicate_hashes(recs("pbkdf2")) == []


def test_md5_precomputed_table_costs_one_pass_for_all_users():
    res = ps.md5_precomputed_attack(recs("md5"), WORDLIST)
    assert res["hashes_computed"] == len(WORDLIST)
    assert set(res["cracked"]) == {"asha", "ben", "dina"}


def test_pbkdf2_costs_attacker_per_user_work():
    md5_work = ps.md5_precomputed_attack(recs("md5"), WORDLIST)["hashes_computed"]
    pbk_work = ps.dictionary_attack(recs("pbkdf2"), WORDLIST)["hashes_computed"]
    assert pbk_work > md5_work  # no sharing across users, and each hash is slow


def test_pbkdf2_still_falls_to_a_weak_password_but_not_a_strong_one():
    cracked = ps.dictionary_attack(recs("pbkdf2"), WORDLIST)["cracked"]
    assert cracked.get("dina") == "dragon"      # slow hashing cannot save a weak password
    assert "chen" not in cracked


def test_verify_accepts_right_and_rejects_wrong_password():
    for kind in ("plain", "md5", "pbkdf2"):
        rec = recs(kind)[0]
        assert ps.verify(rec, "welcome1")
        assert not ps.verify(rec, "wrong")


def test_same_password_gets_different_salt_and_hash():
    a = ps.store_pbkdf2("u1", "same", iterations=FAST)
    b = ps.store_pbkdf2("u2", "same", iterations=FAST)
    assert a.salt != b.salt and a.stored != b.stored


# ---------- phishing analyzer ----------

def test_legit_email_is_clean():
    rep = eml("legit.eml")
    assert rep.auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert rep.findings == [] and rep.verdict == "CLEAN"


def test_spoofed_ceo_email_flags_auth_and_reply_to():
    rep = eml("phish_spoof.eml")
    codes = {f.code for f in rep.findings}
    assert {"spf_fail", "dkim_fail", "dmarc_fail", "reply_to_mismatch", "return_path_mismatch"} <= codes
    assert rep.verdict == "PHISHING-LIKELY"


def test_lookalike_domain_passes_auth_but_is_still_caught():
    rep = eml("phish_lookalike.eml")
    assert rep.auth == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}  # attacker owns the domain
    codes = {f.code for f in rep.findings}
    assert "lookalike_domain" in codes and "link_mismatch" in codes
    assert rep.verdict == "PHISHING-LIKELY"


def test_lookalike_detection_variants():
    assert pa.lookalike_of("northwlnd.example") == "northwind.example"
    assert pa.lookalike_of("northwind-secure.example") == "northwind.example"
    assert pa.lookalike_of("northwind.example") is None
    assert pa.lookalike_of("unrelated.example") is None


def test_parse_auth_results_defaults_to_none():
    assert pa.parse_auth_results("") == {"spf": "none", "dkim": "none", "dmarc": "none"}
