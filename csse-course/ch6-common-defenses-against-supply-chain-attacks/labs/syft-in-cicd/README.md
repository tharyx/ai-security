# Lab: How to Embed Syft into CI/CD pipeline

**Course exercise:** "How to Embed Syft into CI/CD pipeline". Lesson: [06-automating-controls-in-ci-cd.md](../../06-automating-controls-in-ci-cd.md#11-a-gitlab-style-layout). Chapter guide: [README](../../README.md). Real-tool guides: [real-tools](../../real-tools/README.md).

**Time:** 50 minutes. **Tests:** 10, all offline. **Safety:** fixtures only; secrets are FAKE, domains are `.example`, advisory ids are fictional, nothing is downloaded or executed, and tests never need Docker, Kubernetes, a network or an account.

> **Outdated to current.** Named tool: **Syft in GitLab CI**. Syft is actively maintained; pin the Syft image by version or digest in CI.

## What the offline twin does

`pipeline_runner.py` is a **mini GitLab-CI runner**: it reads a `.gitlab-ci.yml` fixture (stages, jobs, `rules`), runs a **simulated `syft` command** against an in-memory workspace, archives the SBOM as an **artifact**, and runs an `sbom-check` gate job. `lint_pipeline()` checks that the tool image is pinned, the SBOM is archived with retention, and the job has rules. Nothing real is executed.

## Steps

```text
.venv/Scripts/python csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/syft-in-cicd/demo.py
.venv/Scripts/python -m pytest csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/syft-in-cicd -v
```

1. Run the demo on `main` and on `feature-x`. Why does the gate fail on the feature branch? (No SBOM was produced there.) Is that desirable?
2. Remove `expire_in` and read the lint message.
3. Change the rules so the SBOM job runs on merge requests too.

## Expected output (real run)

```text
branch main: jobs={'build': 'success', 'sbom': 'success', 'gate': 'success'} artifacts=['sbom.cdx.json']
branch feature-x: jobs={'build': 'success', 'sbom': 'skipped', 'gate': 'failed'} artifacts=[]
log (main): ['building', 'syft: cataloged 3 packages -> sbom.cdx.json', 'sbom-check: 3 components OK']
lint good pipeline: []
lint weakened pipeline: ['sbom: tool image is not pinned to a version or digest', 'sbom: SBOM artifact has no expire_in (decide a retention period)']
```

## Real-tool guide (hedged: verify commands against the current docs)

```yaml
# .gitlab-ci.yml (shape; verify image names and flags)
sbom:
  stage: package
  image:
    name: anchore/syft:<pinned-version>
    entrypoint: [""]
  script:
    - syft dir:. -o cyclonedx-json=sbom.cdx.json
  artifacts:
    paths: [sbom.cdx.json]
    expire_in: 90 days
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH || $CI_COMMIT_TAG'
```
Then sign and attach the SBOM (`cosign attest --type cyclonedx`), upload it to an SBOM store such as Dependency-Track, and scan it (`grype sbom:sbom.cdx.json`). See [real-tools/gitlab.md](../../real-tools/gitlab.md).
