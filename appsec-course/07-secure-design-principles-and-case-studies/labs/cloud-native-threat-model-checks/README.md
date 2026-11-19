# Lab: Checking S3, Kubernetes and vsftpd configurations against their threat models

**Course topics:** [CTMP 5] "Case Study of AWS S3 Threat Model", "Case Study of Kubernetes Threat Model", "Case Study of Very Secure FTP daemon". Lessons: [02 S3](../../02-case-study-aws-s3-threat-model.md), [03 Kubernetes](../../03-case-study-kubernetes-threat-model.md), [04 vsftpd](../../04-case-study-vsftpd.md).

**Time:** 60 minutes. **Tests:** 8, all offline. **Safety:** JSON and text fixtures with fictional names and the documentation-example account id `111122223333`; the only "password" is labelled FAKE. No cloud API, cluster or FTP server is used. Only test systems you own or have written permission to test.

## Goal

A threat model lists mitigations; this lab turns the mitigations of the three case studies into checks over configuration, so a pipeline can prove they are in place. Each check carries the threat id from the lesson's table (S3-T*, K8S-T*, FTP-T*).

## Concept

[cn_checks.py](cn_checks.py):

- `check_s3(bucket)`: Block Public Access, unconditional `Principal: "*"`, TLS-only deny, Object Ownership, encryption suited to the data, versioning and Object Lock, logging, confused-deputy conditions on service principals, `s3:*` grants.
- `check_k8s(objects)`: host namespaces, hostPath, service account token automount, privileged/escalation/capabilities, non-root and read-only root filesystem, image pinning, limits, literal secrets in env, Pod Security Admission label, RBAC wildcards, anonymous bindings, default-deny NetworkPolicy.
- `check_vsftpd(text)`: anonymous access and upload, chroot, forced TLS, `nopriv_user`, transfer log, write access only with chroot.

Fixtures: an insecure and a hardened version of each ([fixtures/](fixtures)). Kubernetes manifests are JSON (Kubernetes accepts JSON as well as YAML).

## Steps

```text
.venv/Scripts/python appsec-course/07-secure-design-principles-and-case-studies/labs/cloud-native-threat-model-checks/demo.py
.venv/Scripts/python -m pytest appsec-course/07-secure-design-principles-and-case-studies/labs/cloud-native-threat-model-checks -q -p no:cacheprovider
```

1. Run the demo: every insecure fixture fails every check; every hardened one passes.
2. For each failing check, find the row in the lesson's threat table and name the principle it implements.
3. Add a condition `"aws:PrincipalOrgID"` to the insecure bucket's public statement: S3-T2 passes, but S3-T1 still fails. Why are both layers needed (defense in depth)?
4. In the hardened Deployment set `image` to `:latest`; only K8S-T6 fails.

## Expected output (real run of demo.py)

```text
== AWS S3 (insecure): 0/9 mitigations in place, gate exit code 1 ==
  FAIL S3-T1    shop-exports-insecure              Block Public Access: all four settings on
  FAIL S3-T2    shop-exports-insecure              no unconditional Allow to Principal '*' (found: ['PublicRead'])
  FAIL S3-T3    shop-exports-insecure              Deny when aws:SecureTransport is false (TLS only)
  FAIL S3-T4    shop-exports-insecure              Object Ownership = BucketOwnerEnforced (ACLs disabled)
  FAIL S3-T5    shop-exports-insecure              encryption at rest suited to the data (sse=AES256; sensitive data -> SSE-KMS)
  FAIL S3-T6    shop-exports-insecure              versioning on; Object Lock for critical data (ransomware, accidental delete)
  FAIL S3-T7    shop-exports-insecure              server access logs or CloudTrail data events
  FAIL S3-T8    shop-exports-insecure              service principals restricted by aws:SourceAccount/SourceArn (confused deputy) (found: ['LogDelivery'])
  FAIL S3-T9    shop-exports-insecure              no s3:* in Allow statements (found: ['PartnerAll'])
== AWS S3 (hardened): 9/9 mitigations in place, gate exit code 0 ==

== Kubernetes (insecure): 0/12 mitigations in place, gate exit code 1 ==
  FAIL K8S-T9   Namespace/shop                     Pod Security Admission enforce=restricted (is privileged)
  FAIL K8S-T1   Deployment/orders-api              no hostNetwork / hostPID / hostIPC
  FAIL K8S-T2   Deployment/orders-api              no hostPath volumes
  FAIL K8S-T3   Deployment/orders-api              automountServiceAccountToken: false unless the pod calls the API
  FAIL K8S-T4   Deployment/orders-api/api          not privileged, allowPrivilegeEscalation false, drop ALL capabilities
  FAIL K8S-T5   Deployment/orders-api/api          runAsNonRoot and readOnlyRootFilesystem
  FAIL K8S-T6   Deployment/orders-api/api          image pinned (tag or digest, not latest): registry.example/shop/orders-api:latest
  FAIL K8S-T7   Deployment/orders-api/api          CPU and memory limits set (resource exhaustion)
  FAIL K8S-T8   Deployment/orders-api/api          secrets come from secretKeyRef or a vault, not literal env values (found: ['DB_PASSWORD'])
  FAIL K8S-T10  ClusterRole/ci-deployer            RBAC rules without '*' verbs or resources
  FAIL K8S-T11  ClusterRoleBinding/debug-anon      no bindings to anonymous users (found: ['system:unauthenticated'])
  FAIL K8S-T12  Namespace/shop                     default-deny NetworkPolicy present
== Kubernetes (hardened): 11/11 mitigations in place, gate exit code 0 ==

== vsftpd (insecure): 0/7 mitigations in place, gate exit code 1 ==
  FAIL FTP-T1   vsftpd.conf                        anonymous_enable=NO (defaults differ between versions and distro packages: set it explicitly)
  FAIL FTP-T2   vsftpd.conf                        no anonymous upload or mkdir
  FAIL FTP-T3   vsftpd.conf                        chroot_local_user=YES (users jailed to their home)
  FAIL FTP-T4   vsftpd.conf                        TLS on and forced for logins and data (otherwise passwords in clear text)
  FAIL FTP-T5   vsftpd.conf                        nopriv_user is a dedicated unprivileged account
  FAIL FTP-T6   vsftpd.conf                        transfer logging on (repudiation)
  FAIL FTP-T7   vsftpd.conf                        write access only when users are jailed
== vsftpd (hardened): 7/7 mitigations in place, gate exit code 0 ==
```

## Run the real tool (hedged)

- **S3:** `aws s3api get-public-access-block --bucket <b>`, `get-bucket-policy`, `get-bucket-ownership-controls`, `get-bucket-encryption`, `get-bucket-versioning`; IAM Access Analyzer; AWS Config rules such as `s3-bucket-public-read-prohibited` and `s3-bucket-ssl-requests-only` (verify names); Prowler or Checkov on Terraform.
- **Kubernetes:** `kubectl get deploy -o json` piped to the lab, or **kube-bench** (CIS), **kubescape**, **Trivy** (`trivy config`), **Checkov**, **Polaris**; enforce with Pod Security Admission, Kyverno or OPA Gatekeeper.
- **vsftpd:** review `/etc/vsftpd.conf` (path varies by distribution) with `man vsftpd.conf`; Lynis and CIS benchmarks include FTP checks; better, replace FTP with SFTP.

## What you learned

- Threat model mitigations become configuration checks with stable threat ids.
- Managed services and platforms (S3, Kubernetes) are secure only with secure configuration: the shared responsibility is yours.
- A secure design (vsftpd privilege separation) can still be configured insecurely.
