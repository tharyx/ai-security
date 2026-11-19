import tempfile
from pathlib import Path

import pytest

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "spoof")

needs_git = pytest.mark.skipif(not s.git_available(), reason="git not available")
needs_ssh = pytest.mark.skipif(not s.ssh_signing_available(), reason="git or ssh-keygen not available")


@needs_git
def test_author_identity_is_free_text():
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        repo = s.init_repo(root, None)
        s.commit(repo, root, "a.txt", "x\n", "fake", "Linus Impostor", "ceo@example.com")
        info = s.read_log(repo, root)[0]
        assert (info.author, info.email) == ("Linus Impostor", "ceo@example.com")
        assert info.sig_status == "N"  # nothing proves who wrote it


@needs_git
def test_unsigned_commit_is_not_trusted():
    with tempfile.TemporaryDirectory() as t:
        rows = s.run_scenario(Path(t))
    assert rows[1].subject == "spoofed, unsigned"
    assert rows[1].email == "alice@example.com" and not s.trusted(rows[1])


@needs_ssh
def test_legit_signed_commit_is_trusted_and_spoofs_are_not():
    with tempfile.TemporaryDirectory() as t:
        rows = s.run_scenario(Path(t))
    assert [s.trusted(r) for r in rows] == [True, False, False]
    assert rows[0].sig_status == "G"
    assert rows[2].sig_status != "G"  # signed, but by a key that is not Alice's


@needs_ssh
def test_wrong_key_signature_differs_from_unsigned():
    with tempfile.TemporaryDirectory() as t:
        rows = s.run_scenario(Path(t))
    assert rows[1].sig_status == "N" and rows[2].sig_status != "N"


def test_allowed_signers_line_format():
    with tempfile.TemporaryDirectory() as t:
        pub = Path(t) / "k.pub"
        pub.write_text("ssh-ed25519 AAAAFAKEBLOB comment\n")
        line = s.allowed_signers_line("a@example.com", pub)
        assert line == 'a@example.com namespaces="git" ssh-ed25519 AAAAFAKEBLOB\n'
