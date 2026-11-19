# Lab: Typosquatting attack in docker image

**Course exercise:** "Typosquatting attack in docker image". Lessons: [03 section 2.3](../../03-attacking-the-container-supply-chain.md#23-typosquatting-and-name-confusion). Related: [CAISP package-vetting lab](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/README.md).

**Time:** 45 minutes. **Safety:** names only; nothing is pulled.

## What it does

[name_sim.py](name_sim.py) parses Docker image references (Docker Hub shortcuts included: `nginx` means `docker.io/library/nginx:latest`) and flags:

- one-edit or two-edit variants (`nginxx`),
- swapped letters (`ngnix`, `ubunut`),
- look-alike characters (`rn` for `m`, `q` for `g`),
- trust words (`redis-official`),
- the same image name under a **different namespace** (`nginx/nginx`).

[fixtures/policy.json](fixtures/policy.json) holds the **allowed registries**, popular names and `require_digest`. `evaluate` returns the problems for a reference.

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/typosquatting-image/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/typosquatting-image -v
```

1. Read the demo. Which references pass? (Only the digest-pinned official image and the internal registry image.)
2. Add `library/mysql` to `popular` and test `mysq1`.
3. Remove `docker.io` from allowed registries: public pulls now need a mirror.
4. Limits: a detector based on names cannot stop a new, creative name. Pair it with allowlists, internal mirrors, signatures and publisher verification.

## Expected output (real run, abridged)

```text
nginx                                        -> not pinned by digest
library/nginx@sha256:fffffffffffffffffffffff -> OK
nqinx                                        -> possible typosquat of library/nginx: look-alike characters (homoglyph); not pinned by digest
ngnix                                        -> possible typosquat of library/nginx: two letters swapped; not pinned by digest
nginx/nginx                                  -> possible typosquat of library/nginx: same name 'nginx' under a different namespace 'nginx'; not pinned by digest
evil-registry.example/library/nginx@sha256:f -> registry evil-registry.example is not on the allowlist
registry.corp.example/team/api@sha256:ffffff -> OK
```

## Real-tool twin

Docker Hub "Docker Official Image" and "Verified Publisher" badges, registry allowlists (Harbor proxy cache), admission policies, and scanners such as Trivy for what runs inside.
