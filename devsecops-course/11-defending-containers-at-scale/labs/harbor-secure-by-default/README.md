# Lab: Securing container images by default using Harbor

**Course exercise:** "Securing Container Images by Default Using Harbor" [CCSE 4]. Lesson: [04 section 3](../../04-trust-registries-and-cicd.md#3-registry-security).

**Time:** 30 minutes. **Safety:** JSON fixtures only.

**Link, do not repeat:** the Harbor setup walk-through is [csse ch6 harbor-registry-policy](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/harbor-registry-policy/README.md). Do it first. This lab turns the project settings into an audit and a pull decision you can test.

## What it does

[project_policy.py](project_policy.py) audits a Harbor-style project (public/private, auto-scan, prevent-vulnerable threshold, signature required, member roles, robot accounts) and answers `may_pull(project, image)`. "Secure by default" means the **default project** you create is already private, scanned and gated, so a team cannot forget to turn it on.

Field names are this lab's own: map them to the Harbor UI/API in your version (verify at source).

## Steps

```text
.venv/Scripts/python devsecops-course/11-defending-containers-at-scale/labs/harbor-secure-by-default/demo.py
.venv/Scripts/python -m pytest devsecops-course/11-defending-containers-at-scale/labs/harbor-secure-by-default -v
```

1. Audit [project_default.json](fixtures/project_default.json) (what a careless admin creates).
2. Compare with [project_hardened.json](fixtures/project_hardened.json).
3. Test the pulls: critical image, unsigned image, unscanned image. Which rule blocks each?
4. Set the threshold to `critical` and read the new finding: a HIGH image can still be pulled.

## Expected output (real run)

```text
== project_default.json: 6 finding(s)
  - project is public: anyone can pull
  - auto-scan on push is off
  - no 'prevent vulnerable images from running' threshold
  - signature (cosign/Notation) not required to pull
  - member dev1 is project_admin without approval
  - robot robot$ci is over-privileged or long-lived
  pull {'max_severity': 'low', 'signed': True, 'scanned': True} -> (True, 'allowed')
  pull {'max_severity': 'critical', 'signed': True, 'scanned': True} -> (True, 'allowed')
  pull {'max_severity': 'low', 'signed': False, 'scanned': True} -> (True, 'allowed')
== project_hardened.json: 0 finding(s)
  pull {'max_severity': 'low', 'signed': True, 'scanned': True} -> (True, 'allowed')
  pull {'max_severity': 'critical', 'signed': True, 'scanned': True} -> (False, 'has critical vulnerabilities (threshold high)')
  pull {'max_severity': 'low', 'signed': False, 'scanned': True} -> (False, 'unsigned image')
```

## Run the real tool (hedged)

Harbor (CNCF graduated) runs from an installer or Helm chart, with Trivy as its default scanner in recent versions. Project settings: Public off, "Automatically scan images on push", "Prevent vulnerable images from running" with a severity, and "Cosign/Notation" signature enforcement (options differ by version). See [real-tools](../../real-tools/README.md).
