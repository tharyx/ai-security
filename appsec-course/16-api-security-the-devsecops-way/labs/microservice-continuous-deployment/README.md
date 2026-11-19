# Lab: Deploying microservices using continuous deployment (admission, rolling, canary, rollback)

**Course items:** "Deploying a Microservice(s) Using Continuous Deployment", "Continuous Integration and Continuous Deployment". Lesson: [03 section 4](../../03-api-security-at-scale-and-cicd.md#4-deploying-microservices-using-continuous-deployment). Related: [csse ch1 continuous-deployment](../../../../csse-course/ch1-introduction-to-supply-chain-security/labs/continuous-deployment/README.md) (environments and protected prod), [devsecops ch01 deployment strategies](../../../../devsecops-course/01-devops-devsecops-and-maturity/02-cicd-and-deployment-strategies.md).

**Time:** 45 minutes. **Tests:** 8, all offline. **Safety:** an in-memory model of clusters and images; nothing is deployed. The signing key is FAKE and generated at runtime. Only test systems you own or have written permission to test.

## Goal

Three API microservices (`orders`, `payments`, and a `gateway` that depends on both) move from v1 to v2. The deploy job must:

1. refuse images that are not **pinned by digest**, not **signed**, or did not pass the **security gates**;
2. promote to **prod** only a digest that already succeeded in **staging**;
3. deploy in **dependency order** (backends before the gateway);
4. **roll back automatically** when a health check fails (rolling) or when the canary's error rate is too high (canary).

## Concept

[cd.py](cd.py): `Deployer.admit()` (the admission policy), `order()` (topological sort), `rolling()`, `canary()`, `deploy()` and an audit trail. The signature is a simulated cosign-style check (HMAC over the digest with a lab key); real cosign uses asymmetric or keyless (Sigstore) signatures.

## Run

```text
.venv/Scripts/python appsec-course/16-api-security-the-devsecops-way/labs/microservice-continuous-deployment/demo.py
.venv/Scripts/python -m pytest appsec-course/16-api-security-the-devsecops-way/labs/microservice-continuous-deployment -v
```

## Expected output (real run)

```text
Deploy order: ['orders', 'payments', 'gateway']

1. Staging, rolling update to v2
   orders    deployed
   payments  rolled-back
   gateway   skipped: a dependency did not deploy
   payments replicas after rollback are all v1: True

2. Production: admission policy
   orders    rejected: orders: image must be pinned by digest, got 'registry.example/orders:latest'; orders: digest never succeeded in staging
   payments  rejected: payments: security gates (SCA/SAST/DAST) did not pass for this digest; payments: digest never succeeded in staging
   gateway   rejected: gateway: digest never succeeded in staging

3. Production canary for orders v2 (staging-approved, but error rate 8%)
   result: {'orders': 'rolled-back'}

Audit trail:
   staging: orders rolled out to 3 replicas
   staging: payments rolled back after replica 1 failed health check
   prod: orders rejected by admission policy
   prod: payments rejected by admission policy
   prod: gateway rejected by admission policy
   prod: orders canary 10%: error rate 8.0% vs stable 0.5%
   prod: orders canary rejected, traffic back to stable
```

## Steps

1. Staging: `payments` v2 fails its health check on the first replica and is rolled back; the `gateway` is skipped because a dependency did not deploy. Why is "deploy the gateway anyway" risky?
2. Prod: three rejections. Map each to the risk it prevents (tag repointing, skipping security scans, promoting a build that never ran in staging). The signature check is exercised in the tests: an image signed with another key is refused, which stops an image pushed by an attacker with registry access.
3. The orders canary is healthy but its error rate is 8% against 0.5%. Rolling back on **metrics**, not only on health checks, catches broken authorization and logic bugs.
4. Change `max_error_rate` and the "2 × stable" rule. Which is safer for a low-traffic service?
5. Add a rule: prod deploys need two approvers (four-eyes), recorded in the audit trail.

## What you learned

- Continuous deployment is safe only with **automated gates and automated rollback**.
- Immutable digests plus signatures plus "same digest from staging to prod" make the release traceable.
- Health checks catch crashes; canary metrics catch bad behaviour.

## Run the real tool (hedged)

- Kubernetes rolling updates with readiness probes (`maxUnavailable`, `maxSurge`); **Argo Rollouts** or **Flagger** for canaries with metric analysis; **Argo CD** or **Flux** for GitOps.
- Admission: **Kyverno** or **OPA Gatekeeper** policies requiring digests and **cosign** signatures (`cosign verify`), Sigstore policy-controller. See [csse ch6 cosign lab](../../../../csse-course/ch6-common-defenses-against-supply-chain-attacks/labs/cosign-container-signing/README.md).
