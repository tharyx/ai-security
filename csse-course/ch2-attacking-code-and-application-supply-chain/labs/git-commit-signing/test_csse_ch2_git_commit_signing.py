import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

g = load_lab_module(__file__, "signing")
needs_ssh = pytest.mark.skipif(not g.ssh_signing_available(), reason="git or ssh-keygen not available")


# ---- real SSH signing ----
@needs_ssh
def test_signed_commit_verifies():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        pub = g.make_key(root, "alice_key")
        repo = g.setup_signing_repo(root, "alice@example.com", pub)
        g.signed_commit(repo, root, "a.txt", "hello\n", "first signed commit")
        ok, msg = g.verify(repo, root)
        assert ok, msg
        assert g.status_letter(repo, root) == "G"


@needs_ssh
def test_tampered_commit_loses_signature():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        pub = g.make_key(root, "alice_key")
        repo = g.setup_signing_repo(root, "alice@example.com", pub)
        g.signed_commit(repo, root, "a.txt", "hello\n", "first signed commit")
        g.tamper_message(repo, root, "changed after the fact")
        ok, _ = g.verify(repo, root)
        assert not ok and g.status_letter(repo, root) == "N"


@needs_ssh
def test_signature_by_unlisted_key_is_not_good():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        alice = g.make_key(root, "alice_key")
        repo = g.setup_signing_repo(root, "alice@example.com", alice)
        other = g.make_key(root, "other_key")
        g.git(repo, root, "config", "user.signingkey", other.as_posix())  # sign with a key not in allowed_signers
        g.signed_commit(repo, root, "a.txt", "hello\n", "signed by someone else")
        assert g.status_letter(repo, root) != "G"
        assert not g.verify(repo, root)[0]


# ---- pure-Python fallback: always runs ----
SECRET = b"toy-shared-secret-not-for-real-use"


def payload():
    return g.commit_payload("T" * 40, "P" * 40, "Alice Real <alice@example.com>", "fix bug")


def test_toy_signature_verifies():
    p = payload()
    assert g.toy_verify(p, g.toy_sign(p, SECRET), SECRET)


def test_toy_signature_detects_content_change():
    p = payload()
    sig = g.toy_sign(p, SECRET)
    tampered = p.replace(b"fix bug", b"fix bug and add backdoor")
    assert not g.toy_verify(tampered, sig, SECRET)
    assert g.commit_id(tampered) != g.commit_id(p)  # the id changes too: hash chain


def test_toy_signature_detects_author_change():
    p = payload()
    sig = g.toy_sign(p, SECRET)
    spoof = p.replace(b"Alice Real", b"Bob Else")
    assert not g.toy_verify(spoof, sig, SECRET)


def test_toy_signature_needs_the_right_key():
    p = payload()
    assert not g.toy_verify(p, g.toy_sign(p, b"attacker-key"), SECRET)
