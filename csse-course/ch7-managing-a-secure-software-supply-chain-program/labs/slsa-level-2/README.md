# Lab: Achieving SLSA Level 2 using GitLab/GitHub

**Course exercise:** "Achieving SLSA Level 2 using GitLab/github". Lessons: [03 section 2](../../03-standards-and-frameworks.md#2-slsa-supply-chain-levels-for-software-artifacts). Related: [CMCPSE sign-verify-mcp-build](../../../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build/README.md), [model-signing](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/).

**Time:** 45 minutes. **Safety:** fake keys, no network.

## What it teaches

L2 = a **hosted build platform** that **signs** the provenance. The consumer then checks four things, which are the four checks of this lab's `verify()`:

| Check | Why |
|---|---|
| **Signature** valid | the file was not edited or hand-written |
| **Builder identity on an allowlist** | a signature from an unknown builder proves nothing |
| **Digest match** | the provenance is about this exact artifact (stops replaying provenance of another build) |
| **Source repo (and ref)** | exact match; `app-evil` must not pass for `app` |

**HMAC twin.** The real thing uses **Sigstore** (a short-lived certificate bound to the CI job's OIDC identity, plus a transparency-log entry) or an asymmetric key held by the platform. HMAC is symmetric, so the verifier needs the same secret as the builder: this is a teaching shortcut. The envelope is **DSSE**-shaped (`payloadType`, `payload`, `signatures`) with a PAE function; verify the exact format in the DSSE spec.

Key test: `test_l1_only_provenance_fails_l2_policy`. An unsigned but complete statement gets `level=1` and a reason, never `ok`.

## Steps

```text
.venv/Scripts/python csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/slsa-level-2/demo.py
.venv/Scripts/python -m pytest csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/slsa-level-2 -v
```

1. Run the demo and read the five verdicts.
2. In `test_builder_id_claim_swapped_breaks_signature` the attacker relabels the payload as the trusted builder. Why does it fail? (The signature covers the payload bytes; the attacker lacks the trusted key.)
3. Make `verify()` use `startswith` for the repo and watch `test_repo_prefix_trick_fails` fail.
4. Think: if the attacker controls the *build steps* on the hosted builder, can they still get a valid signature? Yes. That is the gap between L2 and L3 (isolation, unforgeable provenance).
5. In your course lab: compare with `gh attestation verify` or `slsa-verifier` ([real-tools](../../real-tools/slsa-github-gitlab.md)).

## Expected output (real run)

```text
signed by trusted builder      ok=True  level=2  []
L1 only (unsigned)             ok=False level=1  ['no signature: self-attested provenance is L1 at best']
unknown builder                ok=False level=1  ["builder 'https://attacker.example/builder' is not on the allowlist"]
artifact swapped               ok=False level=0  ['subject digest does not match the artifact']
payload edited after signing   ok=False level=1  ['signature does not verify for the claimed builder']
```

Tests: 16.
