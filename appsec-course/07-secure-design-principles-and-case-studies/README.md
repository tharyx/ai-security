# Chapter 07: Secure Design Principles and Case Studies

This chapter gives you the vocabulary of secure design: Saltzer and Schroeder's eight principles (economy of mechanism, fail-safe defaults, complete mediation, open design, separation of privilege, least privilege, least common mechanism, psychological acceptability), each with a vulnerable and a principled code example. It then applies them to three classic threat models: **AWS S3** (a managed cloud service), **Kubernetes** (a cloud-native platform) and **vsftpd** (a native daemon designed for security). Two offline labs test the principles in code and check S3 policies, Kubernetes manifests and vsftpd configuration against the case studies' mitigations.

> **Safety.** Every lab is a simulation: in-memory SQLite, fictional users and tenants, JSON and text configuration fixtures. No cloud API, cluster or FTP server is touched. Only test systems you own or have written permission to test.

> **Unofficial companion.** Your course videos and lab environment are the primary source. Tool status and version numbers are hedged: **verify at the source**.

## Syllabus coverage

| Syllabus item | Where to study | Lab |
|---|---|---|
| [CTMP 5] Exploring Principles of Secure Design with Examples | [01 section 1](01-secure-design-principles.md#1-exploring-principles-of-secure-design-with-examples) (SVG) | [secure-design-principles](labs/secure-design-principles/README.md) |
| [CTMP 5] Principle of Economy of Mechanism | [01 section 2](01-secure-design-principles.md#2-principle-of-economy-of-mechanism) | [secure-design-principles](labs/secure-design-principles/README.md) (`ManyPathAuth` vs `OnePathAuth`) |
| [CTMP 5] Principle of Fail Safe Defaults | [01 section 3](01-secure-design-principles.md#3-principle-of-fail-safe-defaults) | [secure-design-principles](labs/secure-design-principles/README.md) (`allowed_fail_open` vs `allowed_fail_safe`) |
| [CTMP 5] Principle of Complete Mediation | [01 section 4](01-secure-design-principles.md#4-principle-of-complete-mediation) | [secure-design-principles](labs/secure-design-principles/README.md) (`CachedAuthz` vs `MediatedAuthz`) |
| [CTMP 5] Principle of Open Design | [01 section 5](01-secure-design-principles.md#5-principle-of-open-design) | [secure-design-principles](labs/secure-design-principles/README.md) (`obscure_token` vs `open_token`) |
| [CTMP 5] Principle of Separation of Privilege | [01 section 6](01-secure-design-principles.md#6-principle-of-separation-of-privilege) | [secure-design-principles](labs/secure-design-principles/README.md) (two-person refunds) |
| [CTMP 5] Principle of the Least Privilege | [01 section 7](01-secure-design-principles.md#7-principle-of-least-privilege) | [secure-design-principles](labs/secure-design-principles/README.md) (read-only report connection) |
| [CTMP 5] Principle of the Least Common Mechanism | [01 section 8](01-secure-design-principles.md#8-principle-of-least-common-mechanism) | [secure-design-principles](labs/secure-design-principles/README.md) (per-tenant cache) |
| [CTMP 5] Principle of Psychological Acceptability | [01 section 9](01-secure-design-principles.md#9-principle-of-psychological-acceptability) | [secure-design-principles](labs/secure-design-principles/README.md) (usable password policy) |
| [CTMP 5] Case Study of AWS S3 Threat Model | [Lesson 02](02-case-study-aws-s3-threat-model.md#3-threat-table-ids-match-the-lab) | [cloud-native-threat-model-checks](labs/cloud-native-threat-model-checks/README.md) (S3-T1 to T9) |
| [CTMP 5] Case Study of Kubernetes Threat Model | [Lesson 03](03-case-study-kubernetes-threat-model.md#3-threat-table-ids-match-the-lab-where-checked) | [cloud-native-threat-model-checks](labs/cloud-native-threat-model-checks/README.md) (K8S-T1 to T12) |
| [CTMP 5] Case Study of Very Secure FTP daemon | [Lesson 04](04-case-study-vsftpd.md#2-the-design) (SVG) | [cloud-native-threat-model-checks](labs/cloud-native-threat-model-checks/README.md) (FTP-T1 to T7) |

## Outdated in the syllabus → current

| Syllabus wording | What to know now (Nov 2026; verify at source) |
|---|---|
| Eight principles only | Saltzer and Schroeder also named **work factor** and **compromise recording**; modern lists add defense in depth, secure by default, zero trust (NIST SP 800-160, CISA Secure by Design). |
| Password examples with complexity and rotation | **NIST SP 800-63B-4** (final 2025): length over complexity, blocklists, no forced rotation; passkeys preferred for MFA. |
| **AWS S3** threat model with public-bucket defaults | Since **April 2023** new buckets have **Block Public Access on and ACLs disabled** by default; since **January 2023** objects are encrypted with **SSE-S3** by default. Existing buckets keep their settings. |
| **Kubernetes** threat model (2019 audit) | Still the reference DFD, but **PodSecurityPolicy was removed in 1.25**; use **Pod Security Admission** (or Kyverno/Gatekeeper). Bound service account tokens are default. A 2022 re-audit exists (verify). |
| **vsftpd** as a current file transfer choice | Still a model of secure design, but FTP is legacy: prefer **SFTP** or HTTPS-based transfer. The vsftpd 2.3.4 download was backdoored in 2011: verify signatures. |

## How the three courses overlap here

- **CTMP 5 only** owns this chapter. Least privilege and authorization models return in the API course ([chapter 11](../11-api-authorization-and-oauth/README.md)); BOLA is a complete-mediation failure.
- Container hardening in depth (images, runtime, admission) is in the [DevSecOps course chapters 09 to 12](../../devsecops-course/11-defending-containers-at-scale/README.md); this chapter uses Kubernetes as a threat modeling case.
- Cloud controls per provider: [enterprise architecture multi-cloud matrix](../../09-enterprise-architecture/05-multi-cloud-control-matrix-and-shared-responsibility.md).

## Learning order

1. [Lesson 01](01-secure-design-principles.md) and the [secure-design-principles lab](labs/secure-design-principles/README.md). About 3 hours.
2. [Lesson 02 S3](02-case-study-aws-s3-threat-model.md). About 1 hour.
3. [Lesson 03 Kubernetes](03-case-study-kubernetes-threat-model.md). About 1.5 hours.
4. [Lesson 04 vsftpd](04-case-study-vsftpd.md). About 1 hour.
5. The [cloud-native-threat-model-checks lab](labs/cloud-native-threat-model-checks/README.md). About 1 hour.

## Lab index

All labs run offline: `.venv/Scripts/python -m pytest appsec-course/07-secure-design-principles-and-case-studies -q -p no:cacheprovider`.

| Lab | Course topics | Tests |
|---|---|---|
| [secure-design-principles](labs/secure-design-principles/README.md) | The eight principles with examples | 8 |
| [cloud-native-threat-model-checks](labs/cloud-native-threat-model-checks/README.md) | S3, Kubernetes and vsftpd case studies | 8 |

## Exam tips

- **Memorise the eight** with one violation each: many auth paths; fail open; cached permissions; secret token format; one approver; owner account for reports; shared cache; password rules people hate.
- **Open design = Kerckhoffs:** only keys are secret.
- **Complete mediation** is the principle behind BOLA and VPD.
- **S3:** Block Public Access, no unconditional `Principal: "*"`, TLS-only deny, BucketOwnerEnforced, SSE-KMS for sensitive, versioning/Object Lock, data events logging, `aws:SourceAccount` for service principals.
- **Kubernetes:** API server and etcd are crown jewels; container → node escape (privileged, hostPath, hostPID); service account tokens; RBAC wildcards; default-deny NetworkPolicy; Pod Security Admission (PSP is gone).
- **vsftpd:** privilege separation, unprivileged chrooted network process, tiny privileged interface, minimal parsing with privileges, secure defaults.

## Interview / exam questions

<details>
<summary>1. Who defined the classic secure design principles and when?</summary>

Jerome Saltzer and Michael Schroeder, "The Protection of Information in Computer Systems", 1975. Eight principles plus work factor and compromise recording.
</details>

<details>
<summary>2. Explain economy of mechanism with an example.</summary>

Keep security mechanisms small and simple so they can be reviewed and tested. Example: one authentication middleware for all routes instead of cookies, API keys and a forgotten legacy header that trusts any caller.
</details>

<details>
<summary>3. What are fail-safe defaults?</summary>

Access is denied unless explicitly granted, and errors deny. Examples: default-deny firewall, `acl.get(role, set())`, S3 Block Public Access on by default, default-deny NetworkPolicy.
</details>

<details>
<summary>4. How does complete mediation relate to BOLA?</summary>

Complete mediation requires checking authority on every access to every object. BOLA happens when the API checks only that the user is logged in, not that this user may access this specific object.
</details>

<details>
<summary>5. What does open design mean and what does it not mean?</summary>

Security must not depend on the design being secret; only keys are secret (Kerckhoffs). It does not mean publishing your configuration or keys. A home-made token format fails it; HMAC with a secret key passes.
</details>

<details>
<summary>6. Give three examples of separation of privilege.</summary>

Two-person approval for large refunds or production changes; MFA; a release that needs a passing pipeline and a reviewer who is not the author; KMS key policy plus bucket policy both needed to read encrypted S3 data.
</details>

<details>
<summary>7. How do you apply least privilege to a reporting database account?</summary>

Grant only SELECT on the needed views (or use a read-only replica or authorizer); no DDL, DML or DBA roles. A bug or SQL injection in reporting then cannot change data.
</details>

<details>
<summary>8. Explain least common mechanism with a multi-tenant example.</summary>

Minimise mechanisms shared between users. A cache keyed only by report name leaks tenant A's report to tenant B; keying by tenant and report, or separate caches, removes the shared channel.
</details>

<details>
<summary>9. Why is psychological acceptability a security principle?</summary>

If security is hard to use, people work around it (sticky notes, `Summer2026!`, disabled checks). Usable controls (passphrases, passkeys, secure defaults) are applied correctly and routinely.
</details>

<details>
<summary>10. Name five S3 threats and their mitigations.</summary>

Public exposure (Block Public Access); unconditional public policy (conditions or CloudFront OAC); HTTP access (deny when `aws:SecureTransport` is false); ACL abuse (BucketOwnerEnforced); ransomware/deletion (versioning, Object Lock); no audit trail (CloudTrail data events); confused deputy (`aws:SourceAccount`).
</details>

<details>
<summary>11. What are the key trust boundaries in a Kubernetes threat model?</summary>

Internet to ingress, container to node, pod to API server (service account token), namespace to namespace, node to control plane and etcd, cluster to cloud account, and image supply chain to cluster.
</details>

<details>
<summary>12. How does an attacker escape from a pod to the node, and how do you stop it?</summary>

Privileged containers, hostPath mounts (for example the runtime socket), host PID/network namespaces, extra capabilities. Stop it with Pod Security Admission `restricted`, no hostPath, drop ALL capabilities, non-root, seccomp, and admission policies.
</details>

<details>
<summary>13. What replaced PodSecurityPolicy?</summary>

Pod Security Admission (built in, with privileged, baseline and restricted profiles via namespace labels), or policy engines such as Kyverno and OPA Gatekeeper. PSP was removed in Kubernetes 1.25.
</details>

<details>
<summary>14. Describe vsftpd's privilege separation.</summary>

The network-facing process that parses all FTP commands runs as an unprivileged user in a chroot; a small privileged helper performs only a few root-only operations through a narrow, validated interface. A parsing bug yields an unprivileged, jailed process.
</details>

<details>
<summary>15. vsftpd is "very secure"; how can a vsftpd server still be insecure?</summary>

Through configuration (anonymous access and upload, no chroot, no TLS so passwords travel in clear text, root as nopriv_user) or supply chain (the 2011 backdoored 2.3.4 download). Check the config in CI, verify package signatures, and prefer SFTP for new systems.
</details>

## References

- J. H. Saltzer and M. D. Schroeder (1975); NIST SP 800-160 Vol. 1; CISA Secure by Design.
- AWS Security best practices for Amazon S3; TrustOnCloud ThreatModel for Amazon S3 (verify).
- CNCF Kubernetes security audit and threat model (2019), 2022 re-audit, TAG Security whitepaper; Kubernetes Pod Security Standards; CIS Kubernetes Benchmark.
- vsftpd design notes (Chris Evans); OpenSSH privilege separation paper (Provos et al., 2003).
- Repo: [chapter 06](../06-threat-model-tools-reporting-and-ai/README.md), [devsecops-course containers](../../devsecops-course/11-defending-containers-at-scale/README.md).

**Next chapter:** [Chapter 08: API fundamentals and architecture](../08-api-fundamentals-and-architecture/README.md)
