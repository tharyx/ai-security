# Lab: Kubernetes service accounts

**Course exercise:** "Kubernetes service accounts". Lessons: [01](../../01-microservices-and-kubernetes.md), [04 section 3.2](../../04-common-attack-vectors-in-kubernetes-clusters.md#32-compromised-pod-and-stolen-service-account-token).

**Time:** 45 minutes. **Safety:** tokens are FAKE (three base64url parts, placeholder signature). The lab does not verify signatures; real clusters do.

## Ideas

- A pod's token lets it call the API as `system:serviceaccount:<ns>:<name>`.
- **Automount:** unless `automountServiceAccountToken: false` (on the pod or its ServiceAccount), every pod gets a token it may never need.
- **Bound tokens (projected volumes):** signed JWTs with an **audience**, an **expiry** and a **binding to the pod**. They stop working when the pod is deleted. Legacy Secret-based tokens never expire.
- **Audience:** a token for Vault must not be accepted by another service. `token_review` models that.
- A JWT payload is only encoded. Anyone can read the claims; only the signature check proves authenticity.

## Checks (`sa_check.py`)

| ID | Meaning |
|---|---|
| SA-001 | token mounted but the workload is not marked as needing the API |
| SA-002 | uses the `default` ServiceAccount |
| SA-003, SA-004 | projected token without an audience; lifetime over one hour |
| SA-005 | ServiceAccount references a long-lived token Secret |

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/service-accounts/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/service-accounts -v
```

1. Set `automountServiceAccountToken: false` on the `sloppy` pod and re-run.
2. Replay a token to another audience and read the denial.
3. Real cluster: `kubectl create token web -n shop --duration=10m`, then decode the payload.

## Expected output (real run, abridged)

```text
  [HIGH  ] SA-005 ServiceAccount/shop/legacy-sa: references a long-lived token Secret; ...
  [HIGH  ] SA-001 Pod/shop/sloppy: API token is mounted but the workload is not marked as needing the Kubernetes API ...
== token review ==
  bound, right audience   : OK   valid bound token
  bound, replayed to Vault: DENY audience mismatch: ...
  bound, pod deleted      : DENY bound pod no longer exists
  legacy secret token     : OK   ACCEPTED but legacy: no expiry, no audience, no pod binding ...
```
