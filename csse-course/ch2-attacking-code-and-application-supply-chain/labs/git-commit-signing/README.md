# Lab: Git commit signing

**Course exercise:** "Git commit signing". Lessons: [07 section 2](../../07-best-practices-for-securing-the-application-supply-chain.md#2-code-signing-and-commit-signing). Previous: [git-commit-spoofing](../git-commit-spoofing/README.md). Related: [CAISP ch6 model-signing](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/), [CMCPSE sign-verify](../../../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build/).

**Time:** 40 minutes. **Safety:** ephemeral ed25519 key in a temp dir, a temp repo, isolated git config, no network. Real-signing tests skip if `git` or `ssh-keygen` is missing. The pure-Python fallback always runs.

## Part 1: real SSH signing

`signing.py` configures a repo exactly as a developer would:

```text
git config gpg.format ssh
git config user.signingkey <path to .pub>
git config commit.gpgsign true
git config gpg.ssh.allowedSignersFile <file>      # lines: <email> namespaces="git" <key type> <key>
```

Then it commits (signed), runs `git verify-commit HEAD`, then rewrites the commit without a signature (`--amend --no-gpg-sign`) and verifies again. SSH signing needs a reasonably recent git (about 2.34 or newer; verify).

## Part 2: pure-Python concept fallback

`toy_sign` and `toy_verify` use an HMAC over a commit-like payload (tree, parent, author, message). They show the two properties of a signature: **content** (change one byte, verification fails) and **identity** (only the key holder can sign). HMAC is symmetric, so this is a teaching stand-in; real SSH signatures are asymmetric, so verifiers only need the public key.

## Run

```text
.venv/Scripts/python csse-course/ch2-attacking-code-and-application-supply-chain/labs/git-commit-signing/demo.py
.venv/Scripts/python -m pytest csse-course/ch2-attacking-code-and-application-supply-chain/labs/git-commit-signing
```

## Expected output (real run; the key fingerprint changes every run)

```text
signed commit verifies: True | %G? = G
verify output: Good "git" signature for alice@example.com with ED25519 key SHA256:...
after unsigned amend verifies: False | %G? = N
toy: original ok = True
toy: tampered ok = False
```

## Break it yourself

1. Sign with a second key that is not in `allowed_signers` (the test does this). What is `%G?`? (Not `G`.)
2. Remove `commit.gpgsign=true` and commit. How would you enforce signing for everyone? (Server-side: protected branches that require signed commits, or a CI check. Client config alone is optional.)
3. Why does the toy fallback use a constant-time compare (`hmac.compare_digest`)? (Avoids leaking how many bytes matched through timing.)

## Real life

GPG and S/MIME signing also exist. Sigstore **gitsign** signs commits with short-lived certificates from an OIDC login (keyless); see [real-tools/osv-scanner-and-syft.md](../../real-tools/osv-scanner-and-syft.md) for the artifact side and verify gitsign's docs at the source.
