# Lab: Kubernetes secrets

**Course exercise:** "Kubernetes secrets". Lessons: [01](../../01-microservices-and-kubernetes.md), [04 section 3.3](../../04-common-attack-vectors-in-kubernetes-clusters.md#33-secrets-exposure).

**Time:** 45 minutes. **Safety:** all keys and values are FAKE.

## Lessons in the lab

1. **base64 is not encryption.** `decode_secret` reverses a Secret's `data` with no key.
2. **Secrets in Git** are leaked to every reader and to history.
3. **Encryption at rest:** `audit_encryption_config` checks an API-server `EncryptionConfiguration`: `identity` first means new Secrets are stored in clear (ENC-002); static-key providers keep the key on the control-plane host (ENC-004); prefer **KMS v2**.
4. **Env vs volume:** `secret_consumption` and `consumption_advice` compare environment variables (leak through dumps, `/proc`, child processes, logs; `envFrom` exposes everything) with read-only volume mounts (mode 0400).

## Steps

```text
.venv/Scripts/python csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-secrets/demo.py
.venv/Scripts/python -m pytest csse-course/ch4-attacking-kubernetes-cluster-supply-chain/labs/k8s-secrets -v
```

1. Swap the provider order in `encryption-config-bad.yaml` and re-run the audit.
2. Remove `defaultMode: 0400` from the volume pod and read the advice.
3. Think: even with encryption at rest, who can still read a Secret? (Anyone with RBAC `get`/`list`, any pod that mounts it, and the API server.) Encryption at rest protects etcd backups and disk, not API access ([stealing-k8s-secrets](../stealing-k8s-secrets/README.md)).

## Expected output (real run, abridged)

```text
decoded Secret (no key needed): {'username': 'shop_app', 'password': 'FAKE-not-a-real-password'}
committed to Git?             : ['Secret/shop/db-credentials']
== encryption-config-bad.yaml ==
  [CRITICAL] ENC-002 identity is the first provider: new secrets are written unencrypted
== encryption-config-good.yaml ==
  [-       ] - no findings
```

## Real tools

`kubectl get secret -o yaml`, `etcdctl` (read-only checks in your lab cluster only), Sealed Secrets, External Secrets Operator, SOPS, HashiCorp Vault, cloud secret managers with CSI driver, KMS plugins. See [chapter 5](../../../ch5-attacking-cloud-supply-chain/README.md) for cloud KMS.
