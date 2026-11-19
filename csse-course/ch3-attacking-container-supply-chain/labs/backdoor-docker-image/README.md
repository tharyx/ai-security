# Lab: Backdooring docker image (listed twice in the syllabus)

**Course exercises:** "Backdooring docker image" (both entries). Lessons: [03 section 2.4](../../03-attacking-the-container-supply-chain.md#24-backdooring-an-image-concept), [05 section 4](../../05-technologies-for-securing-containerized-applications.md#4-image-signing-and-content-trust).

**Time:** 45 minutes. **Safety:** the "backdoor" is a canary comment (`CANARY-BACKDOOR-HARMLESS-MARKER`) in a script that does nothing. The lab models images as JSON and never runs them.

## Scenario

`shop-api:1.0` is good. An attacker with push rights re-pushes the same tag with one extra layer containing `/etc/profile.d/zz-update.sh` and `/docker-entrypoint.d/10-warmup.sh`. Teams that pull by tag run the new image. Teams that pinned the digest get a mismatch.

## Files

- [verify.py](verify.py): `layer_digest`, `image_digest`, `diff_images`, `find_canaries`, `autorun_additions`, `verify_pin`, and a toy `TagStore`.
- [fixtures/original.json](fixtures/original.json), [fixtures/backdoored.json](fixtures/backdoored.json).

## Steps

```text
.venv/Scripts/python csse-course/ch3-attacking-container-supply-chain/labs/backdoor-docker-image/demo.py
.venv/Scripts/python -m pytest csse-course/ch3-attacking-container-supply-chain/labs/backdoor-docker-image -v
```

1. Run the demo. Notice that the tag is unchanged and the digest is not.
2. Change one byte in a lower layer instead of adding a layer. The diff shows a *changed* layer, not an added one.
3. Add a signature check in your head: the pin proves "same bytes as before"; a cosign signature adds "built by the release workflow". You need both ideas.

## Expected output (real run)

```text
pull by tag        : no check, runs new content
pull by pinned digest: REFUSED - digest mismatch: pinned sha256:14921b582b39... but got sha256:9e0dbd620e64...
added layers       : [2]
added files        : ['/docker-entrypoint.d/10-warmup.sh', '/etc/profile.d/zz-update.sh']
autorun locations  : ['/docker-entrypoint.d/10-warmup.sh', '/etc/profile.d/zz-update.sh']
canary hits        : [(2, '/etc/profile.d/zz-update.sh'), (2, '/docker-entrypoint.d/10-warmup.sh')]
```

## Real-tool twin

`docker pull image@sha256:...`, `crane digest`, `skopeo inspect`, `cosign verify`. Related: [CMCPSE backdoor-mcp-package](../../../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/backdoor-mcp-package/README.md).
