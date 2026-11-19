# SLSA provenance on GitHub and GitLab (outline)

> **Status: hedged outline, not tested by the repo author.** Features and level claims change. Check: <https://slsa.dev>, <https://github.com/slsa-framework/slsa-github-generator>, GitHub docs on artifact attestations, and GitLab docs on build provenance.

**Course exercises:** Achieving SLSA Level 1 / Level 2 using GitLab/GitHub.
**Offline twins (tested):** [slsa-level-1](../labs/slsa-level-1/README.md) and [slsa-level-2](../labs/slsa-level-2/README.md). The YAML fixtures in `slsa-level-1/fixtures/` are the shapes below.

## GitHub (use a repository you own)

**Level 1 (provenance exists):** any scripted workflow that publishes a provenance file with the artifact reaches the idea of L1. In practice use a standard tool rather than writing it yourself.

**Level 2 and up:**
1. Reusable workflow route: call `slsa-framework/slsa-github-generator` (generic generator for any build output) as a job after your build job; pass the artifact hashes (base64 `sha256sum` output). Reference the reusable workflow by its release tag as its docs say. The generator targets L3 for supported builders; check the docs.
2. Attestation route: GitHub artifact attestations (`actions/attest-build-provenance`) sign provenance with Sigstore using the workflow's OIDC identity (`id-token: write`, `attestations: write`). The level you can claim depends on how the workflow is isolated: read GitHub's SLSA documentation.
3. **Pin every other action to a full commit SHA**; give the workflow least-privilege `permissions`.

**Verify (the consumer side, the important half):**

```text
# conceptual; check each tool's current flags
slsa-verifier verify-artifact my-artifact --provenance-path my-artifact.intoto.jsonl \
    --source-uri github.com/<org>/<repo> --source-tag v1.0.0
gh attestation verify my-artifact --repo <org>/<repo>
cosign verify-attestation --type slsaprovenance1 ...   # for container images (options vary)
```

These do what `verify()` does in the offline lab: signature, builder identity, digest, source repo and ref.

## GitLab (use a project you own)

- GitLab CI: `.gitlab-ci.yml` with stages and jobs; protected branches and tags, protected and masked CI/CD variables, and runners (shared vs project/group runners; prefer ephemeral runners for builds).
- **Provenance:** GitLab Runner can generate artifact metadata, a provenance-style statement, when `RUNNER_GENERATE_ARTIFACTS_METADATA: "true"` is set (see the fixture). Newer GitLab versions describe signing and attestations for artifacts and for container images (including keyless signing options through Sigstore/OIDC ID tokens). Check which GitLab version and tier you have and what level GitLab claims.
- **Pipeline hygiene:** `rules:` to restrict release jobs to protected tags, no secrets in merge-request pipelines from forks, scope project and group access tokens narrowly and rotate them, and review who can change CI configuration (the GitLab privilege-escalation ideas: over-broad Maintainer roles, tokens that outlive their need).
- Offline lab note: `analyze_pipeline_yaml` shows how a tool can inspect these files; it is a heuristic, not a GitLab feature.

## What to record in your notes

- Which builder identity appears in the provenance?
- Which fields prove the source commit?
- What would an attacker with only a stolen release token be unable to do? (Produce provenance for your builder identity.)
- At which level does your setup stand, and why not higher?
