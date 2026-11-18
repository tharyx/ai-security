# Module 06 — AI DevSecOps: Secure SDLC, Supply Chain and Runtime

**Effort:** 20–26 hours. **Outcome:** Add repeatable security gates to AI application and model delivery.

## 1. Secure AI SDLC
| Stage | Activity | Evidence |
|---|---|---|
| Intake | Purpose, owner, users, risk tier | AI intake record |
| Design | Threat model, data flow, privacy review | Architecture approval |
| Build | Secure coding, dependency/secret checks | CI reports |
| Model/data | Provenance, license, integrity, evaluation | Model/data inventory |
| Test | SAST, DAST, LLM/RAG/agent tests | Test report |
| Release | Artifact integrity, approval, rollback | Release record |
| Operate | Monitoring, quotas, incident response | Dashboards/runbooks |
| Retire | Revoke, delete, archive evidence | Decommission record |

## 2. Model and data supply chain
Track model/provider/version and digest where available; tokenizer/runtime; dataset origin/license/classification/legal basis; fine-tuning adapters/config; dependencies; evaluation suite/results; artifact location/access/integrity; approvals and changes. Threats include malicious model files, compromised dependencies, poisoned datasets, unauthorized adapters and unreviewed upgrades.

## 3. CI/CD gates
1. Secret scan.
2. SAST and dependency audit.
3. Unit and authorization tests.
4. Prompt injection/data leakage regression.
5. RAG tenant-isolation tests.
6. MCP tool authorization tests.
7. Model/data provenance validation.
8. Container scan and SBOM.
9. Artifact signing and protected deployment.
10. Staging runtime security tests.
11. Production approval.

Example GitHub Actions workflow:
```yaml
name: ai-security
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements-dev.txt
      - run: pytest -q
      - run: pip-audit -r requirements.txt
      - run: pytest -q tests/security/
```
For production, pin actions to verified full commit SHAs, protect environments, restrict job permissions and prefer OIDC federation over static cloud keys.

## 4. Container/Kubernetes hardening
Run non-root; read-only root filesystem where practical; drop capabilities; use seccomp/AppArmor; set CPU/memory limits; network policies and egress controls; workload identity; avoid hostPath/Docker socket; managed secrets; pin images by digest; enforce admission policies and provenance; separate namespaces/service accounts.

## 5. Runtime telemetry
Collect principal/tenant IDs, model/provider/version, prompt template version, policy decision, retrieval source IDs and authorization result, tool/server/action identifiers, approval ID, token/cost/latency metrics and correlation IDs. Avoid indiscriminate logging of raw prompts, documents, bearer tokens or personal data.

## 6. Incident scenarios
Prepare playbooks for prompt injection with exposure, unauthorized RAG retrieval, MCP credential compromise, agent action outside scope, model supply-chain tampering, runaway cost/DoS and sensitive telemetry.

## Lab
Build a CI pipeline for the capstone. Introduce a failing security test and prove release is blocked. Change model version and demonstrate evaluation reruns. Add dependency audit and least-privilege CI identity.

## Acceptance criteria
CI has security regressions; dependencies/model artifacts inventoried; no static cloud keys where federation is available; containers hardened; logs attributable/redacted; incident runbooks tabletop-tested.
