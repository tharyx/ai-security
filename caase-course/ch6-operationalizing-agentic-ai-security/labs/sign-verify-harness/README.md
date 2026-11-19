# Lab: Signing and Verifying an Agent Harness (HMAC twin and real cosign)

**Syllabus exercise:** Signing and Verifying an Agent Harness Using Cosign · **Lesson:** [05](../../05-aibom-provenance-and-signing.md) · **Offline, 9 tests.** Builds on [CAISP model-signing](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing) and [cmcpse sign-verify-mcp-build](../../../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build).

## Offline twin

`sign_harness.py`: `build_manifest()` hashes every file (path to SHA-256), `sign()` signs the canonical manifest with HMAC-SHA256, `verify()` checks the key id is trusted, the algorithm is expected, the signature is valid, manifest paths are safe, and then **re-hashes the directory**: modified, missing and extra files are all rejected.

```text
.venv/Scripts/python -m pytest caase-course/ch6-operationalizing-agentic-ai-security/labs/sign-verify-harness
.venv/Scripts/python caase-course/ch6-operationalizing-agentic-ai-security/labs/sign-verify-harness/demo.py
```

Real output:

```text
untouched harness: verified
prompt edited: REJECTED (file modified: prompt.md)
backdoor skill added: REJECTED (unsigned extra file(s): ['skills/x.md'])

Real commands this twin mirrors (not run here):
  cosign generate-key-pair
  cosign sign-blob --key cosign.key --bundle harness.bundle manifest.json
  cosign verify-blob --key cosign.pub --bundle harness.bundle manifest.json
```

**Why it is only a twin:** HMAC is symmetric, so a verifier could forge signatures. Cosign uses asymmetric keys or keyless identity.

## Real cosign (hedged: not executed by the repo's tests or author)

Run this in your course lab or a throwaway folder. Check `cosign --help` and the Sigstore docs for your version; flags change.

```text
# 1. install cosign (see the Sigstore docs for your OS)
# 2. make a manifest of your harness folder, e.g. with the lab's build_manifest() written to manifest.json
cosign generate-key-pair                      # creates cosign.key and cosign.pub (set a password)
cosign sign-blob --key cosign.key --bundle harness.bundle manifest.json
cosign verify-blob --key cosign.pub --bundle harness.bundle manifest.json
# change one byte in manifest.json and verify again: it must fail
```

Keyless signing in CI (OIDC identity, transparency log) uses `cosign sign-blob` without a key and `cosign verify-blob` with `--certificate-identity` and `--certificate-oidc-issuer`. After the signature check, still re-hash the files against the manifest, as the lab's `verify()` does.

## Break it yourself

1. Remove the `alg` check: add a test that forges `alg: none` and see what a careless verifier would accept.
2. Let `verify()` ignore extra files. Which attack is now possible?
3. Stretch: sign the AIBOM from [aibom-harness](../aibom-harness/README.md) as well and verify both at startup.
