# Lab: Sign an MCP Server Build and Verify Its Integrity on Deployment

**Course exercise:** "Sign an MCP server build and verify its integrity on deployment". Lesson: [03 transparency and integrity, signing](../../03-transparency-and-integrity.md#4-mcp-server-signing-concepts-and-implementation). General model-signing lab: [CAISP model-signing](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/labs/model-signing/).

**Time:** 45 minutes. Offline. The build is a fixture (`fixtures/build_src/`, three files). The signing key is a **FAKE** lab key.

## The offline twin

```text
build   -> manifest {name, version, files: {path: sha256}}  -> canonical JSON -> HMAC-SHA256 -> bundle
deploy  -> verify signature -> re-hash every file on disk -> no unlisted files -> name -> no rollback
```

`signing.py` has `build_manifest`, `canonical`, `sign`, `verify_bundle` and `deploy`. `verify_bundle` **fails closed** and reports every problem it finds.

| Attack | What the deploy gate says |
|---|---|
| Change `server.py` after signing | `content changed after signing: server.py` |
| Add a file (a new "tool") | `unlisted file present (not signed): ...` |
| Delete a file | `missing file: ...` |
| Edit the manifest hash to match the new code | `signature does not match the manifest` |
| Wrong or unknown key | `signature ...` / `unknown signing key id` |
| Replay an older, validly signed version | `rollback: version 1.0.0 is older than 1.1.0` |
| `../` path in the manifest | `manifest path escapes the deploy folder` |

**HMAC is only a stand-in.** It is symmetric: whoever can verify can also sign (the last test proves it). In real life use asymmetric signatures (Sigstore/cosign, minisign, GPG, a KMS key) so the verifier holds only a public key or an expected identity.

## Steps

```text
.venv/Scripts/python cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build/demo.py
.venv/Scripts/python -m pytest cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/sign-verify-mcp-build -v
```

1. Run the demo and map each tamper to the check that caught it.
2. Add `mcp-manifest.json`'s tool hashes to the signed manifest as a separate field and make the gate print which tool descriptions changed.
3. Add an `expires` field to the bundle and refuse stale bundles.
4. Think: if an attacker controls the **build** machine, does signing help? (No: it signs whatever the build produced. That is why provenance and a hardened builder matter: [provenance lab](../provenance-attestations/README.md).)

## Expected output (real run)

```text
signature: d2bed9054dc13b0e481b71caf48baf3d ...
files signed: ['mcp-manifest.json', 'requirements.lock', 'server.py']
deploy: deployed notes-mcp 1.2.0

-- tamper 1: change the server code after signing
['content changed after signing: server.py']

-- tamper 2: add an extra file
['unlisted file present (not signed): extra_tool.py']

-- tamper 3: edit the manifest hash to match the new code (attacker has no key)
['signature does not match the manifest']

-- rollback: a validly signed OLD version
['rollback: version 1.0.0 is older than 1.1.0']
```

## Optional: the same flow with real cosign (hedged, NOT executed by the repo author)

Install cosign from the official Sigstore instructions; flags change between releases, so check `cosign sign-blob --help` for your version.

```text
# Package the build, then sign the file (keyless: opens a browser for OIDC login, or uses CI OIDC)
tar czf notes-mcp-1.2.0.tar.gz -C fixtures/build_src .
cosign sign-blob --yes --bundle notes-mcp-1.2.0.sigstore.json notes-mcp-1.2.0.tar.gz

# At deploy: verify with the EXPECTED identity and issuer (replace with your own values)
cosign verify-blob --bundle notes-mcp-1.2.0.sigstore.json \
  --certificate-identity you@example.com \
  --certificate-oidc-issuer https://accounts.google.com \
  notes-mcp-1.2.0.tar.gz

# Key-pair alternative (a long-lived key you must protect)
cosign generate-key-pair
cosign sign-blob --key cosign.key --output-signature build.sig notes-mcp-1.2.0.tar.gz
cosign verify-blob --key cosign.pub --signature build.sig notes-mcp-1.2.0.tar.gz
```

Then tamper with the tarball and verify again: verification must fail. Keyless signing records the event in the public Rekor transparency log: do not sign confidential artifacts that way unless you accept that metadata being public (verify the privacy implications in the Sigstore docs).
