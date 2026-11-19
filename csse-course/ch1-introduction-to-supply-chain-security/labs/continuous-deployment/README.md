# Lab: Continuous Deployment (environments, protected prod, rollback)

**Course exercise:** "Continuous Deployment". Lesson: [05 section 2.5](../../05-cicd-stages-and-deployment.md#25-continuous-deployment). Repo background: [deploy_approval](../../../../06-ai-devsecops/cicd/README.md).
**Time:** 40 minutes. **Safety:** in-memory model; nothing is deployed.

## What `cd.py` enforces

| Rule | How it is tested |
|---|---|
| Build once, deploy the same **digest** everywhere | `test_same_digest_everywhere`, digest mismatch rejected |
| Order dev, staging, prod | A version must be in the lower environment first |
| **Prod is protected** | Needs an approval; branch must be protected (`main`) |
| **Separation of duties** | The requester cannot approve; only listed approvers can; only the requester runs the approved deploy |
| Approval is single-use, expires, and is bound to the digest | Swapped artifact is refused |
| Failed health check means **auto-rollback** | Previous release becomes active again |
| **Manual rollback** | Re-deploys an earlier good release (same digest), approver role required in prod |
| Audit trail | Who approved which digest |

## Steps

```text
.venv/Scripts/python csse-course/ch1-introduction-to-supply-chain-security/labs/continuous-deployment/demo.py
.venv/Scripts/python -m pytest csse-course/ch1-introduction-to-supply-chain-security/labs/continuous-deployment -v
```

1. Run the demo; follow the "prod without approval" and "self-approval" lines.
2. Change `approvers` so two approvals are required (four-eyes). Add a test.
3. Add a "canary" step: 10% first, then 100%. Where does the health check go?
4. Think: if rollback re-deployed a rebuilt image instead of the stored digest, what could go wrong? (The rollback artifact would differ from what ran before, and from what was tested.)

## Expected output (real run)

```text
CI built 1.0: sha256:e167b64d93be7539...
CI built 1.1: sha256:7f4218233f8df432...
prod without approval  : prod is protected: manual approval required
self-approval          : alice is not an approver for prod
prod 1.0               : deployed
prod 1.1 (unhealthy)   : rolled_back
state after auto-rollback: {'dev': '1.1', 'staging': '1.1', 'prod': '1.0'}

audit trail:
  artifact_registered  {'version': '1.0'}
  artifact_registered  {'version': '1.1'}
  deployed             {'env': 'dev', 'version': '1.0', 'by': 'ci'}
  deployed             {'env': 'staging', 'version': '1.0', 'by': 'ci'}
  approval_requested   {'env': 'prod', 'version': '1.0', 'by': 'alice'}
  approved             {'env': 'prod', 'version': '1.0', 'approver': 'release-manager'}
  deployed             {'env': 'prod', 'version': '1.0', 'by': 'alice'}
  deployed             {'env': 'dev', 'version': '1.1', 'by': 'ci'}
  deployed             {'env': 'staging', 'version': '1.1', 'by': 'ci'}
  approval_requested   {'env': 'prod', 'version': '1.1', 'by': 'alice'}
  approved             {'env': 'prod', 'version': '1.1', 'approver': 'security-lead'}
  deployed             {'env': 'prod', 'version': '1.1', 'by': 'alice'}
  health_check_failed  {'env': 'prod', 'version': '1.1'}
  auto_rollback        {'env': 'prod', 'to': '1.0'}
```

(The digests depend only on the fake build content, so they are stable.)
