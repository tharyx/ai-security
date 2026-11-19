# Lab: Achieving SLSA Level 1 using GitLab/GitHub

**Course exercise:** "Achieving SLSA Level 1 using GitLab/Github". Lessons: [03 section 2](../../03-standards-and-frameworks.md#2-slsa-supply-chain-levels-for-software-artifacts). Related: [CMCPSE provenance-attestations](../../../../cmcpse-course/ch6-supply-chain-security-and-governance-of-mcp/labs/provenance-attestations/README.md), [CAISP SLSA and SCVS](../../../../caisp-course/ch6-supply-chain-attacks-in-ai/03-supply-chain-frameworks-slsa-and-scvs.md), [workflow lint](../../../../06-ai-devsecops/cicd/README.md).

**Time:** 45 minutes. **Safety:** no build is run; the "pipeline" is a Python function and the YAML files are only parsed.

## What it teaches

SLSA Build **L1** means: the build is scripted, and it produces **provenance** that says what was built, from which source, by which builder. The lab has three parts.

| Part | File | What it does |
|---|---|---|
| Generate | `slsa_provenance.simulate_pipeline` | Emits an in-toto **Statement v1** with a **SLSA provenance v1** predicate (`buildDefinition`, `runDetails`). Field names are from memory: hedge and verify at slsa.dev. |
| Check | `slsa_provenance.check_l1` | Verifies the L1 requirements: statement and predicate types, sha256 subject, digest matches the artifact, builder id, source repo and commit, invocation id. |
| Real pipelines | `fixtures/github-actions-slsa.yml`, `fixtures/gitlab-ci-provenance.yml` | Show the shape of real pipelines: GitHub's `slsa-github-generator` reusable workflow, and GitLab Runner's artifact metadata. `analyze_pipeline_yaml` spots them (and unpinned actions). |

**The honest limit.** L1 provenance is a document anyone can write. The test `test_forged_but_complete_provenance_passes_l1` proves it. [slsa-level-2](../slsa-level-2/README.md) fixes this with signatures.

## Steps

```text
.venv/Scripts/python csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/slsa-level-1/demo.py
.venv/Scripts/python -m pytest csse-course/ch7-managing-a-secure-software-supply-chain-program/labs/slsa-level-1 -v
```

1. Run the demo. Change one byte of the artifact: which requirement fails?
2. Delete `invocationId`, then `source.digest.gitCommit`. Why does each matter to a consumer? (Without the commit you cannot tell which source produced the binary.)
3. Open the two YAML fixtures. Find where the **builder** is named and where the **subject digests** come from.
4. In the GitHub fixture, why does the job need `id-token: write`? (It lets the builder obtain an OIDC identity, which is what makes signing at L2/L3 possible.)
5. In your own course lab: add the generator job to a real repository, download the provenance file, and run `slsa-verifier` on it (see [real-tools](../../real-tools/slsa-github-gitlab.md)).

## Expected output (real run, trimmed)

```text
good             : passed=True []
artifact swapped : passed=False ['subject digest matches the artifact bytes']
no builder id    : ['builder id is present']
round trip equal : True
github-actions-slsa.yml -> {'platform': 'github-actions', 'produces_provenance': True, 'mechanism': 'slsa-github-generator reusable workflow', 'unpinned_actions': []}
gitlab-ci-provenance.yml -> {'platform': 'gitlab-ci', 'produces_provenance': True, 'mechanism': 'GitLab Runner artifacts metadata', 'unpinned_actions': []}
unpinned-no-provenance.yml -> {'platform': 'github-actions', 'produces_provenance': False, 'mechanism': None, 'unpinned_actions': ['actions/checkout@v4']}
```

Tests: 18.
