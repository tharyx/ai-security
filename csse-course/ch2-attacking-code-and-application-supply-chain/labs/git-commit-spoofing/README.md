# Lab: Git commit spoofing

**Course exercise:** "Git commit spoofing". Lessons: [02 section 8](../../02-attacks-on-scm-systems.md#8-commit-spoofing-identity-is-free-text), [07 section 2](../../07-best-practices-for-securing-the-application-supply-chain.md#2-code-signing-and-commit-signing). Next lab: [git-commit-signing](../git-commit-signing/README.md).

**Time:** 30 minutes. **Safety:** a REAL git repository in a temporary directory, using the `git` CLI with an isolated config. Nothing is pushed. Keys are ephemeral, passphrase-less, and deleted with the temp dir. Tests skip if `git` (or `ssh-keygen` for the signature part) is missing.

## What it shows

Git's author and committer fields are free text. The lab makes three commits that all say `Alice Real <alice@example.com>`:

1. A legitimate commit **signed** with Alice's SSH key (the key is listed in `allowed_signers`).
2. A **spoofed, unsigned** commit.
3. A **spoofed commit signed with the attacker's own key**.

Then `git log --format=%G?` reports the signature status. Only the first is trusted.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/git-commit-spoofing/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/git-commit-spoofing
```

## Expected output (real run)

```text
subject                          author       email              sig  trusted
legit change by Alice            Alice Real   alice@example.com  G    True
spoofed, unsigned                Alice Real   alice@example.com  N    False
spoofed, signed by wrong key     Alice Real   alice@example.com  U    False
sig: G=good, N=none, B=bad, U=valid signature, signer not trusted for this identity
```

## Break it yourself

1. Add the attacker's key to `allowed_signers` under Alice's email. What changes? (The spoof becomes "good". This is why the allowed-signers list is a security-critical file, and why changes to it need review.)
2. A platform shows a "Verified" badge only for signatures it can check against keys registered to the account. Why is a bare author name not enough? (See above.)
3. Think about `git commit --author=...` versus `GIT_COMMITTER_NAME`: which fields can be forged? (Both.)

## Real life

Hosting platforms show verification badges for signed commits (verify current behaviour in their docs). Signed commits help **attribution**; they do not make the code safe (a stolen key signs malicious code too). Pair with branch protection that requires signed commits and reviews.
