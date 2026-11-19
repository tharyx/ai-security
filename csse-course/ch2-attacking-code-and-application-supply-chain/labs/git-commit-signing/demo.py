import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import signing as g  # noqa: E402

if g.ssh_signing_available():
    with tempfile.TemporaryDirectory(prefix="csse2-sign-") as t:
        root = Path(t)
        pub = g.make_key(root, "alice_key")
        repo = g.setup_signing_repo(root, "alice@example.com", pub)
        g.signed_commit(repo, root, "a.txt", "hello\n", "first signed commit")
        ok, msg = g.verify(repo, root)
        print("signed commit verifies:", ok, "| %G? =", g.status_letter(repo, root))
        print("verify output:", msg.splitlines()[0] if msg else "")
        g.tamper_message(repo, root, "changed after the fact")
        ok, _ = g.verify(repo, root)
        print("after unsigned amend verifies:", ok, "| %G? =", g.status_letter(repo, root))
else:
    print("git or ssh-keygen missing: only the concept fallback runs")

p = g.commit_payload("T" * 40, "P" * 40, "Alice Real <alice@example.com>", "fix bug")
sig = g.toy_sign(p, b"toy-shared-secret-not-for-real-use")
print("toy: original ok =", g.toy_verify(p, sig, b"toy-shared-secret-not-for-real-use"))
print("toy: tampered ok =", g.toy_verify(p.replace(b"fix bug", b"add backdoor"), sig, b"toy-shared-secret-not-for-real-use"))
